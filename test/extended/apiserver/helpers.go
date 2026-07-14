package apiserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"
	exutil "github.com/openshift/origin/test/extended/util"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

const (
	asAdmin                   = true
	withoutNamespace          = true
	defaultRegistryServiceURL = "image-registry.openshift-image-registry.svc:5000"
)

func getTestDataFilePath(filename string) string {
	return filepath.Join(exutil.FixturePath("testdata", "apiserver"), filename)
}

func getRandomString(digit int) string {
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	buffer := make([]byte, digit)
	for index := range buffer {
		buffer[index] = chars[seed.Intn(len(chars))]
	}
	return string(buffer)
}

func getRandomNum(m int32, n int32) int32 {
	rand.Seed(time.Now().UnixNano())
	return rand.Int31n(n-m+1) + m
}

func doAction(oc *exutil.CLI, action string, isAdmin bool, noNamespace bool, parameters ...string) (string, error) {
	if isAdmin && noNamespace {
		return oc.AsAdmin().WithoutNamespace().Run(action).Args(parameters...).Output()
	}
	if isAdmin && !noNamespace {
		return oc.AsAdmin().Run(action).Args(parameters...).Output()
	}
	if !isAdmin && noNamespace {
		return oc.WithoutNamespace().Run(action).Args(parameters...).Output()
	}
	if !isAdmin && !noNamespace {
		return oc.Run(action).Args(parameters...).Output()
	}
	return "", nil
}

func getResource(oc *exutil.CLI, isAdmin bool, noNamespace bool, parameters ...string) (string, error) {
	return doAction(oc, "get", isAdmin, noNamespace, parameters...)
}

func getResourceToBeReady(oc *exutil.CLI, isAdmin bool, noNamespace bool, parameters ...string) string {
	var result string
	var err error
	errPoll := wait.PollUntilContextTimeout(context.Background(), 6*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
		result, err = doAction(oc, "get", isAdmin, noNamespace, parameters...)
		if err != nil || len(result) == 0 {
			e2e.Logf("Unable to retrieve the expected resource, retrying...")
			return false, nil
		}
		return true, nil
	})
	assertWaitPollNoErr(errPoll, fmt.Sprintf("Failed to retrieve %v", parameters))
	e2e.Logf("The resource returned:\n%v", result)
	return result
}

func assertWaitPollNoErr(e error, msg string) {
	if e == nil {
		return
	}
	var err error
	if strings.Compare(e.Error(), "timed out waiting for the condition") == 0 || strings.Compare(e.Error(), "context deadline exceeded") == 0 {
		err = fmt.Errorf("case: %v\nerror: %s", g.CurrentSpecReport().FullText(), msg)
	} else {
		err = fmt.Errorf("case: %v\nerror: %s", g.CurrentSpecReport().FullText(), e.Error())
	}
	o.Expect(err).NotTo(o.HaveOccurred())
}

func countResource(oc *exutil.CLI, resource string, namespace string) (int, error) {
	output, err := oc.Run("get").Args(resource, "-n", namespace, "-o", "jsonpath='{.items[*].metadata.name}'").Output()
	output = strings.Trim(strings.Trim(output, " "), "'")
	if output == "" {
		return 0, err
	}
	resources := strings.Split(output, " ")
	return len(resources), err
}

func getNodePortRange(oc *exutil.CLI) (int, int) {
	output, err := oc.AsAdmin().Run("get").Args("configmaps", "-n", "openshift-kube-apiserver", "config", `-o=jsonpath="{.data['config\.yaml']}"`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	rgx := regexp.MustCompile(`"service-node-port-range":\["([0-9]*)-([0-9]*)"\]`)
	rs := rgx.FindSubmatch([]byte(output))
	o.Expect(rs).To(o.HaveLen(3))

	leftBound, err := strconv.Atoi(string(rs[1]))
	o.Expect(err).NotTo(o.HaveOccurred())
	rightBound, err := strconv.Atoi(string(rs[2]))
	o.Expect(err).NotTo(o.HaveOccurred())
	return leftBound, rightBound
}

func getServiceIP(oc *exutil.CLI, clusterIP string) net.IP {
	var serviceIP net.IP
	err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
		randomServiceIP := net.ParseIP(clusterIP).To4()
		if randomServiceIP != nil {
			randomServiceIP[3] += byte(rand.Intn(254 - 1))
		} else {
			randomServiceIP = net.ParseIP(clusterIP).To16()
			randomServiceIP[len(randomServiceIP)-1] = byte(rand.Intn(254 - 1))
		}
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("service", "-A", `-o=jsonpath={.items[*].spec.clusterIP}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if matched, _ := regexp.MatchString(randomServiceIP.String(), output); matched {
			e2e.Logf("IP %v has been used!", randomServiceIP)
			return false, nil
		}
		serviceIP = randomServiceIP
		return true, nil
	})
	assertWaitPollNoErr(err, "Failed to get one available service IP!")
	return serviceIP
}

func isIPv4(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

func isIPv6(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ":")
}

func checkURLEndpointAccess(oc *exutil.CLI, hostIP, nodePort, podName, portCommand, status string) {
	var url string
	var curlOutput string
	var curlErr error

	if isIPv6(hostIP) {
		url = fmt.Sprintf("[%s]:%s", hostIP, nodePort)
	} else {
		url = fmt.Sprintf("%s:%s", hostIP, nodePort)
	}

	var fullCommand string
	if portCommand == "https" {
		fullCommand = fmt.Sprintf("curl -k https://%s", url)
	} else {
		fullCommand = fmt.Sprintf("curl %s", url)
	}

	e2e.Logf("Command: %v", fullCommand)
	e2e.Logf("Checking if the specified URL endpoint %s is accessible", url)

	err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 6*time.Second, false, func(cxt context.Context) (bool, error) {
		curlOutput, curlErr = oc.Run("exec").Args(podName, "-i", "--", "sh", "-c", fullCommand).Output()
		if curlErr != nil {
			return false, nil
		}
		return true, nil
	})

	assertWaitPollNoErr(err, fmt.Sprintf("Unable to access %s", url))
	o.Expect(curlOutput).To(o.ContainSubstring(status))
}

func execCommandOnPod(oc *exutil.CLI, podname string, namespace string, command string) string {
	var podOutput string
	var execpodErr error

	errExec := wait.PollUntilContextTimeout(context.Background(), 15*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
		podOutput, execpodErr = oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", namespace, podname, "--", "/bin/sh", "-c", command).Output()
		podOutput = strings.TrimSpace(podOutput)
		e2e.Logf("Attempting to execute command on pod %v. Output: %v, Error: %v", podname, podOutput, execpodErr)

		if execpodErr != nil {
			matchTLS, _ := regexp.MatchString(`(?i)tls.*internal error`, podOutput)
			if matchTLS {
				e2e.Logf("Detected TLS error in output for pod %v: %v", podname, podOutput)
				getCsr, getCsrErr := getPendingCSRs(oc)
				if getCsrErr != nil {
					e2e.Logf("Error retrieving pending CSRs: %v", getCsrErr)
					return false, nil
				}
				for _, csr := range getCsr {
					e2e.Logf("Approving CSR: %v", csr)
					appCsrErr := oc.WithoutNamespace().AsAdmin().Run("adm").Args("certificate", "approve", csr).Execute()
					if appCsrErr != nil {
						e2e.Logf("Error approving CSR %v: %v", csr, appCsrErr)
						return false, nil
					}
				}
				e2e.Logf("Pending CSRs approved. Retrying command on pod %v...", podname)
				return false, nil
			}
			e2e.Logf("Command execution error on pod %v: %v", podname, execpodErr)
			return false, nil
		} else if podOutput != "" {
			e2e.Logf("Successfully retrieved non-empty output from pod %v: %v", podname, podOutput)
			return true, nil
		}
		e2e.Logf("Received empty output from pod %v. Retrying...", podname)
		return false, nil
	})

	assertWaitPollNoErr(errExec, fmt.Sprintf("Unable to run command on pod %v :: %v :: Output: %v :: Error: %v", podname, command, podOutput, execpodErr))
	return podOutput
}

func getPendingCSRs(oc *exutil.CLI) ([]string, error) {
	output := getResourceToBeReady(oc, asAdmin, withoutNamespace, "csr")
	o.Expect(output).NotTo(o.BeEmpty())

	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")

	var pendingCSRs []string
	for _, line := range lines {
		if strings.Contains(line, "Pending") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				pendingCSRs = append(pendingCSRs, fields[0])
			}
		}
	}
	return pendingCSRs, nil
}

func copyImageToInternalRegistry(oc *exutil.CLI, namespace string, source string, dest string) (string, error) {
	var (
		podName string
		appName = "skopeo"
		err     error
	)

	podName, _ = oc.AsAdmin().WithoutNamespace().Run("get").Args("pod", "-n", namespace, "-l", "name="+appName, "-o", `jsonpath={.items[*].metadata.name}`).Output()
	if len(podName) == 0 {
		template := getTestDataFilePath("skopeo-deployment.json")
		err = oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		podName = getPodsListByLabel(oc.AsAdmin(), namespace, "name="+appName)[0]
		assertPodToBeReady(oc, podName, namespace)
	} else {
		output, err := oc.AsAdmin().Run("get").Args("pod", podName, "-n", namespace, "-o", "jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("True"), appName+" pod is not ready!")
	}

	token, err := getSAToken(oc, "builder", namespace)
	o.Expect(err).NotTo(o.HaveOccurred())
	o.Expect(token).NotTo(o.BeEmpty())

	command := []string{podName, "-n", namespace, "--", appName, "--insecure-policy", "--src-tls-verify=false", "--dest-tls-verify=false", "copy", "--dcreds", "dnm:" + token, source, dest}
	results, err := oc.AsAdmin().WithoutNamespace().Run("exec").Args(command...).Output()
	return results, err
}

func getSAToken(oc *exutil.CLI, sa, ns string) (string, error) {
	e2e.Logf("Getting a token assigned to specific serviceaccount from %s namespace...", ns)
	token, err := oc.AsAdmin().WithoutNamespace().Run("create").Args("token", sa, "-n", ns).Output()
	if err != nil {
		if strings.Contains(token, "unknown command") {
			e2e.Logf("oc create token is not supported by current client, use oc sa get-token instead")
			token, err = oc.AsAdmin().WithoutNamespace().Run("sa").Args("get-token", sa, "-n", ns).Output()
		} else {
			return "", err
		}
	}
	return token, err
}

func isBaselineCapsSet(oc *exutil.CLI) bool {
	baselineCapabilitySet, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion", "version", "-o=jsonpath={.spec.capabilities.baselineCapabilitySet}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("baselineCapabilitySet parameters: %v\n", baselineCapabilitySet)
	return len(baselineCapabilitySet) != 0
}

func isEnabledCapability(oc *exutil.CLI, component string) bool {
	enabledCapabilities, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("clusterversion", "-o=jsonpath={.items[*].status.capabilities.enabledCapabilities}").Output()
	o.Expect(err).NotTo(o.HaveOccurred())
	e2e.Logf("Cluster enabled capability parameters: %v\n", enabledCapabilities)
	return strings.Contains(enabledCapabilities, component)
}

func createSecretsWithQuotaValidation(oc *exutil.CLI, namespace, clusterQuotaName string, crqLimits map[string]string, caseID string) {
	secretCount, err := oc.Run("get").Args("-n", namespace, "clusterresourcequota", clusterQuotaName, "-o", `jsonpath={.status.namespaces[*].status.used.secrets}`).Output()
	o.Expect(err).NotTo(o.HaveOccurred())

	usedCount, _ := strconv.Atoi(secretCount)
	limits, _ := strconv.Atoi(crqLimits["secrets"])
	steps := 1

	for i := usedCount; i <= limits; i++ {
		secretName := fmt.Sprintf("%v-secret-%d", caseID, steps)
		e2e.Logf("Creating secret %s", secretName)

		output, err := oc.Run("create").Args("-n", namespace, "secret", "generic", secretName).Output()

		if i < limits {
			output1, _ := oc.Run("get").Args("-n", namespace, "secret").Output()
			e2e.Logf("Get total secrets created to debug :: %s", output1)
			o.Expect(err).NotTo(o.HaveOccurred())
		} else {
			if err != nil && strings.Contains(output, "secrets.*forbidden: exceeded quota") {
				e2e.Logf("Quota limit reached, as expected.")
			} else {
				o.Expect(err).To(o.HaveOccurred())
			}
		}
		steps++
	}
}

func getPodsListByLabel(oc *exutil.CLI, namespace string, selectorLabel string) []string {
	podsOp := getResourceToBeReady(oc, asAdmin, withoutNamespace, "pod", "-n", namespace, "-l", selectorLabel, "-o=jsonpath={.items[*].metadata.name}")
	o.Expect(podsOp).NotTo(o.BeEmpty())
	return strings.Split(podsOp, " ")
}

func assertPodToBeReady(oc *exutil.CLI, podName string, namespace string) {
	err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 3*time.Minute, false, func(cxt context.Context) (bool, error) {
		stdout, err := oc.AsAdmin().Run("get").Args("pod", podName, "-n", namespace, "-o", "jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'").Output()
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		if strings.Contains(stdout, "True") {
			e2e.Logf("Pod %s is ready!", podName)
			return true, nil
		}
		return false, nil
	})
	assertWaitPollNoErr(err, fmt.Sprintf("Pod %s status is not ready!", podName))
}

func checkResources(oc *exutil.CLI, dirname string) map[string]string {
	resUsedDet := make(map[string]string)
	resUsed := []string{"secrets", "deployments", "namespaces", "pods"}
	for _, key := range resUsed {
		tmpPath, err := oc.AsAdmin().WithoutNamespace().Run("get").Args(key, "-A", "--no-headers").OutputToFile(dirname)
		o.Expect(err).NotTo(o.HaveOccurred())
		cmd := fmt.Sprintf(`cat %v | wc -l | awk '{print $1}'`, tmpPath)
		output, err := exec.Command("bash", "-c", cmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		resUsedDet[key] = string(output)
	}
	return resUsedDet
}

func applyLabel(oc *exutil.CLI, isAdmin bool, noNamespace bool, parameters ...string) {
	_, err := doAction(oc, "label", isAdmin, noNamespace, parameters...)
	o.Expect(err).NotTo(o.HaveOccurred(), "Adding label to the namespace failed")
}

func getGlobalProxy(oc *exutil.CLI) (string, string, string) {
	httpProxy, err := getResource(oc, asAdmin, withoutNamespace, "proxy", "cluster", "-o=jsonpath={.status.httpProxy}")
	o.Expect(err).NotTo(o.HaveOccurred())
	httpsProxy, err := getResource(oc, asAdmin, withoutNamespace, "proxy", "cluster", "-o=jsonpath={.status.httpsProxy}")
	o.Expect(err).NotTo(o.HaveOccurred())
	noProxy, err := getResource(oc, asAdmin, withoutNamespace, "proxy", "cluster", "-o=jsonpath={.status.noProxy}")
	o.Expect(err).NotTo(o.HaveOccurred())
	return httpProxy, httpsProxy, noProxy
}

func getPodsList(oc *exutil.CLI, namespace string) []string {
	podsOp := getResourceToBeReady(oc, asAdmin, withoutNamespace, "pod", "-n", namespace, "-o=jsonpath={.items[*].metadata.name}")
	podNames := strings.Split(strings.TrimSpace(podsOp), " ")
	e2e.Logf("Namespace %s pods are: %s", namespace, string(podsOp))
	return podNames
}

func waitCoBecomes(oc *exutil.CLI, coName string, baseWaitTime int, expectedStatus map[string]string) error {
	waitTime := baseWaitTime
	stableDelay := 100 * time.Second

	if isSNOCluster(oc) {
		waitTime = baseWaitTime * 3
	}

	errCo := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, time.Duration(waitTime)*time.Second, false, func(cxt context.Context) (bool, error) {
		gottenStatus := getCoStatus(oc, coName, expectedStatus)
		eq := reflect.DeepEqual(expectedStatus, gottenStatus)
		if eq {
			eq := reflect.DeepEqual(expectedStatus, map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"})
			if eq {
				time.Sleep(stableDelay)
				gottenStatus := getCoStatus(oc, coName, expectedStatus)
				eq := reflect.DeepEqual(expectedStatus, gottenStatus)
				if eq {
					e2e.Logf("Given operator %s becomes available/non-progressing/non-degraded", coName)
					return true, nil
				}
			} else {
				e2e.Logf("Given operator %s becomes %s", coName, gottenStatus)
				return true, nil
			}
		}
		return false, nil
	})
	if errCo != nil {
		err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
	}
	return errCo
}

func getCoStatus(oc *exutil.CLI, coName string, statusToCompare map[string]string) map[string]string {
	newStatusToCompare := make(map[string]string)
	for key := range statusToCompare {
		args := fmt.Sprintf(`-o=jsonpath={.status.conditions[?(.type == '%s')].status}`, key)
		status, _ := getResource(oc, asAdmin, withoutNamespace, "co", coName, args)
		newStatusToCompare[key] = status
	}
	return newStatusToCompare
}

func isSNOCluster(oc *exutil.CLI) bool {
	masterOutput, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/master", "-o=jsonpath={.items[*].metadata.name}").Output()
	workerOutput, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("nodes", "-l", "node-role.kubernetes.io/worker", "-o=jsonpath={.items[*].metadata.name}").Output()
	masterNodes := strings.Fields(masterOutput)
	workerNodes := strings.Fields(workerOutput)
	if len(masterNodes) == 1 && len(workerNodes) == 1 && masterNodes[0] == workerNodes[0] {
		return true
	}
	return false
}

func getApiServerFQDNandPort(oc *exutil.CLI) (string, string) {
	apiServerURL, configErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("view", "-ojsonpath={.clusters[0].cluster.server}").Output()
	o.Expect(configErr).NotTo(o.HaveOccurred())
	fqdnName, parseErr := url.Parse(apiServerURL)
	o.Expect(parseErr).NotTo(o.HaveOccurred())
	return fqdnName.Hostname(), fqdnName.Port()
}

func clientCurl(tokenValue string, curlURL string) string {
	timeoutDuration := 3 * time.Second
	var bodyString string

	proxyURL := getProxyURL()

	req, err := http.NewRequest("GET", curlURL, nil)
	if err != nil {
		e2e.Failf("error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+tokenValue)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeoutDuration,
	}

	errCurl := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
		resp, err := client.Do(req)
		if err != nil {
			return false, nil
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			bodyBytes, _ := ioutil.ReadAll(resp.Body)
			bodyString = string(bodyBytes)
			return true, nil
		}
		return false, nil
	})
	assertWaitPollNoErr(errCurl, fmt.Sprintf("error waiting for curl request output: %v", errCurl))
	return bodyString
}

func getProxyURL() *url.URL {
	proxyURLString := os.Getenv("https_proxy")
	if proxyURLString == "" {
		proxyURLString = os.Getenv("http_proxy")
	}
	if proxyURLString == "" {
		return nil
	}
	proxyURL, err := url.Parse(proxyURLString)
	if err != nil {
		e2e.Failf("error parsing proxy URL: %v", err)
	}
	return proxyURL
}

func isTechPreviewNoUpgrade(oc *exutil.CLI) bool {
	featureGate, err := oc.AdminConfigClient().ConfigV1().FeatureGates().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false
		}
		e2e.Failf("could not retrieve feature-gate: %v", err)
	}
	return featureGate.Spec.FeatureSet == configv1.TechPreviewNoUpgrade
}

func processTemplate(oc *exutil.CLI, parameters ...string) string {
	var configFile string
	err := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 15*time.Second, false, func(cxt context.Context) (bool, error) {
		fileName := getRandomString(8) + "config.json"
		stdout, _, err := oc.AsAdmin().Run("process").Args(parameters...).OutputsToFiles(fileName)
		if err != nil {
			e2e.Logf("the err:%v, and try next round", err)
			return false, nil
		}
		configFile = stdout
		return true, nil
	})
	assertWaitPollNoErr(err, fmt.Sprintf("fail to process %v", parameters))
	e2e.Logf("the file of resource is %s", configFile)
	return configFile
}
