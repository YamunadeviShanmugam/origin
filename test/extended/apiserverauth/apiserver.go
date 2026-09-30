package apiserverauth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
	ote "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
	"github.com/tidwall/gjson"
	exutil "github.com/openshift/origin/test/extended/util"
	compat_otp "github.com/openshift/origin/test/extended/util/compat_otp"
	"github.com/openshift/origin/test/extended/util/compat_otp/architecture"
	logger "github.com/openshift/origin/test/extended/util/compat_otp/logext"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

// TODO: The following QE test cases from openshift-tests-private's
// test/extended/apiserverauth/apiserver.go are intentionally NOT YET ported here.
// They are highly invasive/disruptive (cluster-wide outages, deleting core namespaces,
// immutable audit logs, multi-hour encryption/CA rollouts) and need careful, deliberate
// validation against a real cluster before being added. Do not add them without explicit
// sign-off.
//
//   - OCP-63273 - cluster-wide etcd encryption type change [Disruptive][Slow]
//   - OCP-68400 - disables image registry / registry-dependent flow [Disruptive][Slow]
//   - OCP-70396 - client-CA trust configuration change [Disruptive][Slow]
//   - OCP-25926 - wire cipher config into apiserver/authentication operators, multiple
//     ~30min rollouts [Disruptive][Slow]
//   - OCP-36801 - Etcd encrypted cluster self-recovery: deletes the
//     openshift-kube-apiserver and openshift-apiserver namespaces live and watches
//     self-recovery [Slow][Disruptive]
//   - OCP-73879 - Alert KubeAPIDown: iptables DROP on port 6443 on ALL master nodes for
//     5 minutes (full API outage) [Slow][Disruptive]
//   - OCP-73853 - Update alert KubeAPIErrorBudgetBurn: ~50% packet loss on a master's
//     NIC for ~17 minutes [Slow][Disruptive]
//   - OCP-73880 - Alert KubeAggregatedAPIErrors: 2000ms network delay on a master's NIC
//     for 12 minutes [Slow][Disruptive]
//   - OCP-73949 - Update alert AuditLogError: chattr +i (immutable) on audit log files on
//     ALL master nodes [Slow][Disruptive]
//
// Also deferred (lower risk, but blocked/needs extra tooling):
//   - OCP-40861 - API Priority and Fairness stress test ("cluster works fine without panic
//     under stress with API Priority and Fairness feature"): NOT being ported as a separate
//     test. It is a functional duplicate of [OTP][OCP-40667] in
//     test/extended/apiserver/webhooks.go ("Prepare upgrade cluster under APF stress"),
//     which already stresses the cluster under APF using kube-burner (via the unexported
//     loadCPUMemWorkload helper in test/extended/apiserver/helpers.go) and asserts no
//     panics/no-route errors and cluster health - the same assertions OCP-40861 makes.
//   - OCP-10592 - Cluster-admin could get/edit/delete subresource: ID collides with an
//     existing, unrelated, correctly-authored [OTP][OCP-10592] test in
//     test/extended/cluster/audit.go; needs a naming/collision decision before porting.
//
// Low priority / likely skip (flagged flaky or environment-dependent in the source repo):
//   - OCP-34223, OCP-42937, OCP-38865, OCP-39601, OCP-43889
var _ = g.Describe("[sig-api-machinery] API_Server", func() {
	defer g.GinkgoRecover()

	var oc = compat_otp.NewCLIWithoutNamespace("default")
	var tmpdir string

	g.JustBeforeEach(func() {
		tmpdir = "/tmp/-OCP-apisever-cases-" + compat_otp.GetRandomString() + "/"
		err := os.MkdirAll(tmpdir, 0755)
		o.Expect(err).NotTo(o.HaveOccurred())
	})

	g.JustAfterEach(func() {
		os.RemoveAll(tmpdir)
		logger.Infof("test dir %s is cleaned up", tmpdir)
	})

	// author: zxiao@redhat.com
	// This case is for bug 1297910
	g.It("[OTP][OCP-09853] patch operation should use patched object to check admission control", ote.Informing(), func() {
		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By("2) Use admin user to create quota and limits for project")

		compat_otp.By("2.1) Create quota")
		template := getTestDataFilePath("ocp9853-quota.yaml")
		err := oc.AsAdmin().Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2.2) Create limits")
		template = getTestDataFilePath("ocp9853-limits.yaml")
		err = oc.AsAdmin().Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(`2.3) Create pod and wait for "hello-openshift" pod to be ready`)
		template = getTestDataFilePath("hello-pod.json")
		err = oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		podName := "hello-openshift"
		compat_otp.AssertPodToBeReady(oc, podName, namespace)

		compat_otp.By("3) Update pod's image using patch command")
		patch := `{"spec":{"containers":[{"name":"hello-openshift","image":"quay.io/openshifttest/hello-openshift:1.2.0"}]}}`
		output, err := oc.Run("patch").Args("pod", podName, "-n", namespace, "-p", patch).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("patched"))

		compat_otp.By("4) Check if pod running")
		compat_otp.AssertPodToBeReady(oc, podName, namespace)
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-10933] Check if client use protobuf data transfer scheme to communicate with master [platformmanagement_public_768]", ote.Informing(), func() {
		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		filename := "hello-pod.json"
		compat_otp.By(fmt.Sprintf("2) Create pod with resource file %s", filename))
		template := getTestDataFilePath(filename)
		err := oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		podName := "hello-openshift"
		compat_otp.By(fmt.Sprintf("3) Wait for pod with name %s to be ready", podName))
		compat_otp.AssertPodToBeReady(oc, podName, namespace)

		compat_otp.By("4) Check get pods resource and check output")
		output, err := oc.Run("get").Args("pods", podName, "-n", namespace, "-v=8").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring("application/vnd.kubernetes.protobuf"))
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-10970] Create service with multiports [Apiserver]", ote.Informing(), func() {
		var (
			filename  = "pod_with_multi_ports.json"
			filename1 = "pod-for-ping.json"
			podName1  = "hello-openshift"
			podName2  = "pod-for-ping"
		)

		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By(fmt.Sprintf("2) Create pod with resource file %s", filename))
		template := getTestDataFilePath(filename)
		err := oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("3) Wait for pod with name %s to be ready", podName1))
		compat_otp.AssertPodToBeReady(oc, podName1, namespace)

		compat_otp.By(fmt.Sprintf("4) Check host ip for pod %s", podName1))
		hostIP, err := oc.Run("get").Args("pods", podName1, "-o=jsonpath={.status.hostIP}", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(hostIP).NotTo(o.Equal(""))
		e2e.Logf("Get host ip %s", hostIP)

		compat_otp.By("5) Create nodeport service with random service port")
		servicePort1 := rand.Intn(3000) + 6000
		servicePort2 := rand.Intn(6001) + 9000

		serviceErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("service", "nodeport", podName1, fmt.Sprintf("--tcp=%d:8080,%d:8443", servicePort1, servicePort2), "-n", namespace).Execute()
		o.Expect(serviceErr).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("6) Check the service with the node port %s", podName1))
		nodePort1, err := oc.Run("get").Args("services", podName1, fmt.Sprintf("-o=jsonpath={.spec.ports[?(@.port==%d)].nodePort}", servicePort1)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodePort1).NotTo(o.Equal(""))
		nodePort2, err := oc.Run("get").Args("services", podName1, fmt.Sprintf("-o=jsonpath={.spec.ports[?(@.port==%d)].nodePort}", servicePort2)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodePort2).NotTo(o.Equal(""))
		e2e.Logf("Get node port %s :: %s", nodePort1, nodePort2)

		compat_otp.By(fmt.Sprintf("6.1) Create pod with resource file %s for checking network access", filename1))
		template = getTestDataFilePath(filename1)
		err = oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("6.2) Wait for pod with name %s to be ready", podName2))
		compat_otp.AssertPodToBeReady(oc, podName2, namespace)

		compat_otp.By("6.3) Check URL endpoint access")
		checkURLEndpointAccess(oc, hostIP, nodePort1, podName2, "http", "hello-openshift http-8080")
		checkURLEndpointAccess(oc, hostIP, nodePort2, podName2, "https", "hello-openshift https-8443")

		compat_otp.By(fmt.Sprintf("6.4) Delete service %s", podName1))
		err = oc.Run("delete").Args("service", podName1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("7) Create another service with random target ports %d :: %d", servicePort1, servicePort2))
		err1 := oc.Run("create").Args("service", "clusterip", podName1, fmt.Sprintf("--tcp=%d:8080,%d:8443", servicePort1, servicePort2)).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())
		defer oc.Run("delete").Args("service", podName1).Execute()

		compat_otp.By(fmt.Sprintf("7.1) Check cluster ip for pod %s", podName1))
		clusterIP, serviceErr := oc.Run("get").Args("services", podName1, "-o=jsonpath={.spec.clusterIP}", "-n", namespace).Output()
		o.Expect(serviceErr).NotTo(o.HaveOccurred())
		o.Expect(clusterIP).ShouldNot(o.BeEmpty())
		e2e.Logf("Get node clusterIP :: %s", clusterIP)

		compat_otp.By("7.2) Check URL endpoint access again")
		checkURLEndpointAccess(oc, clusterIP, strconv.Itoa(servicePort1), podName2, "http", "hello-openshift http-8080")
		checkURLEndpointAccess(oc, clusterIP, strconv.Itoa(servicePort2), podName2, "https", "hello-openshift https-8443")
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-11364] Create nodeport service [platformmanagement_public_624]", ote.Informing(), func() {
		var (
			generatedNodePort int
			curlOutput        string
			url               string
			curlErr           error
			filename          = "hello-pod.json"
			podName           = "hello-openshift"
		)

		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By(fmt.Sprintf("2) Create pod with resource file %s", filename))
		template := getTestDataFilePath(filename)
		err := oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("3) Wait for pod with name %s to be ready", podName))
		compat_otp.AssertPodToBeReady(oc, podName, namespace)

		compat_otp.By(fmt.Sprintf("4) Check host ip for pod %s", podName))
		hostIP, err := oc.Run("get").Args("pods", podName, "-o=jsonpath={.status.hostIP}", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(hostIP).NotTo(o.Equal(""))
		e2e.Logf("Get host ip %s", hostIP)

		compat_otp.By("5) Create nodeport service with random service port")
		servicePort1 := rand.Intn(3000) + 6000
		serviceName := podName
		err = oc.Run("create").Args("service", "nodeport", serviceName, fmt.Sprintf("--tcp=%d:8080", servicePort1)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("6) Check the service with the node ip and port %s", serviceName))
		nodePort, err := oc.Run("get").Args("services", serviceName, fmt.Sprintf("-o=jsonpath={.spec.ports[?(@.port==%d)].nodePort}", servicePort1)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodePort).NotTo(o.Equal(""))
		e2e.Logf("Get node port %s", nodePort)

		filename = "pod-for-ping.json"
		compat_otp.By(fmt.Sprintf("6.1) Create pod with resource file %s for checking network access", filename))
		template = getTestDataFilePath(filename)
		err = oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		podName = "pod-for-ping"
		compat_otp.By(fmt.Sprintf("6.2) Wait for pod with name %s to be ready", podName))
		compat_otp.AssertPodToBeReady(oc, podName, namespace)

		if isIPv6(hostIP) {
			url = fmt.Sprintf("[%v]:%v", hostIP, nodePort)
		} else {
			url = fmt.Sprintf("%s:%s", hostIP, nodePort)
		}
		compat_otp.By(fmt.Sprintf("6.3) Accessing the endpoint %s with curl command line", url))
		// retry 3 times, sometimes, the endpoint is not ready for accessing.
		err = wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 6*time.Second, false, func(cxt context.Context) (bool, error) {
			curlOutput, curlErr = oc.Run("exec").Args(podName, "-i", "--", "curl", url).Output()
			if err != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Unable to access the %s", url))
		o.Expect(curlErr).NotTo(o.HaveOccurred())
		o.Expect(curlOutput).To(o.ContainSubstring("Hello OpenShift!"))

		compat_otp.By(fmt.Sprintf("6.4) Delete service %s", serviceName))
		err = oc.Run("delete").Args("service", serviceName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		servicePort2 := rand.Intn(3000) + 6000
		npLeftBound, npRightBound := getNodePortRange(oc)
		compat_otp.By(fmt.Sprintf("7) Create another nodeport service with random target port %d and node port [%d-%d]", servicePort2, npLeftBound, npRightBound))
		generatedNodePort = rand.Intn(npRightBound-npLeftBound) + npLeftBound
		err1 := oc.Run("create").Args("service", "nodeport", serviceName, fmt.Sprintf("--node-port=%d", generatedNodePort), fmt.Sprintf("--tcp=%d:8080", servicePort2)).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())
		defer oc.Run("delete").Args("service", serviceName).Execute()

		if isIPv6(hostIP) {
			url = fmt.Sprintf("[%v]:%v", hostIP, generatedNodePort)
		} else {
			url = fmt.Sprintf("%s:%d", hostIP, generatedNodePort)
		}
		compat_otp.By(fmt.Sprintf("8) Check network access again to %s", url))
		err = wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 6*time.Second, false, func(cxt context.Context) (bool, error) {
			curlOutput, curlErr = oc.Run("exec").Args(podName, "-i", "--", "curl", url).Output()
			if err != nil {
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Unable to access the %s", url))
		o.Expect(curlErr).NotTo(o.HaveOccurred())
		o.Expect(curlOutput).To(o.ContainSubstring("Hello OpenShift!"))
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-12360] The number of created API objects can not exceed quota limitation [origin_platformexp_403]", ote.Informing(), func() {
		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()
		limit := 3

		compat_otp.By("2) Get quota limits according to used resouce count under namespace")
		type quotaLimits struct {
			podLimit           int
			resourcequotaLimit int
			secretLimit        int
			serviceLimit       int
			configmapLimit     int
		}

		var limits quotaLimits
		var err error

		limits.podLimit, err = countResource(oc, "pods", namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		limits.podLimit += limit

		limits.resourcequotaLimit, err = countResource(oc, "resourcequotas", namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		limits.resourcequotaLimit += limit + 1 // need to count the quota we added

		limits.secretLimit, err = countResource(oc, "secrets", namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		limits.secretLimit += limit

		limits.serviceLimit, err = countResource(oc, "services", namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		limits.serviceLimit += limit

		limits.configmapLimit, err = countResource(oc, "configmaps", namespace)
		o.Expect(err).NotTo(o.HaveOccurred())
		limits.configmapLimit += limit

		e2e.Logf("Get limits of pods %d, resourcequotas %d, secrets %d, services %d, configmaps %d", limits.podLimit, limits.resourcequotaLimit, limits.secretLimit, limits.serviceLimit, limits.configmapLimit)

		filename := "ocp12360-quota.yaml"
		quotaName := "ocp12360-quota"
		compat_otp.By(fmt.Sprintf("3) Create quota with resource file %s", filename))
		template := getTestDataFilePath(filename)
		params := []string{"-f", template, "-p", fmt.Sprintf("POD_LIMIT=%d", limits.podLimit), fmt.Sprintf("RQ_LIMIT=%d", limits.resourcequotaLimit), fmt.Sprintf("SECRET_LIMIT=%d", limits.secretLimit), fmt.Sprintf("SERVICE_LIMIT=%d", limits.serviceLimit), fmt.Sprintf("CM_LIMIT=%d", limits.configmapLimit), fmt.Sprintf("NAME=%s", quotaName)}
		configFile := compat_otp.ProcessTemplate(oc, params...)
		err = oc.AsAdmin().Run("create").Args("-f", configFile, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4) Wait for quota to show up in command describe")
		quotaDescribeErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, false, func(cxt context.Context) (bool, error) {
			describeOutput, err := oc.Run("describe").Args("quota", quotaName, "-n", namespace).Output()
			if isMatched, matchErr := regexp.Match("secrets.*[0-9]", []byte(describeOutput)); isMatched && matchErr == nil && err == nil {
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(quotaDescribeErr, "quota did not show up")

		compat_otp.By(fmt.Sprintf("5) Create multiple secrets with resource file %s, expect failure for secert creations that exceed quota limit", filename))
		for i := 1; i <= limit+1; i++ {
			secretName := fmt.Sprintf("ocp12360-secret-%d", i)
			output, err := oc.Run("create").Args("secret", "generic", secretName, "--from-literal=testkey=testvalue", "-n", namespace).Output()
			if i <= limit {
				compat_otp.By(fmt.Sprintf("5.%d) creating secret %s, within quota limit, expect success", i, secretName))
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				compat_otp.By(fmt.Sprintf("5.%d) creating secret %s, exceeds quota limit, expect failure", i, secretName))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("secrets.*forbidden: exceeded quota"))
			}
		}

		filename = "ocp12360-pod.yaml"
		compat_otp.By(fmt.Sprintf("6) Create multiple pods with resource file %s, expect failure for pod creations that exceed quota limit", filename))
		template = getTestDataFilePath(filename)
		for i := 1; i <= limit+1; i++ {
			podName := fmt.Sprintf("ocp12360-pod-%d", i)
			configFile := compat_otp.ProcessTemplate(oc, "-f", template, "-p", "NAME="+podName)
			output, err := oc.Run("create").Args("-f", configFile, "-n", namespace).Output()
			if i <= limit {
				compat_otp.By(fmt.Sprintf("6.%d) creating pod %s, within quota limit, expect success", i, podName))
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				compat_otp.By(fmt.Sprintf("6.%d) creating pod %s, exceeds quota limit, expect failure", i, podName))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("pods.*forbidden: exceeded quota"))
			}
		}

		compat_otp.By(fmt.Sprintf("7) Create multiple services with resource file %s, expect failure for resource creations that exceed quota limit", filename))
		for i := 1; i <= limit+1; i++ {
			serviceName := fmt.Sprintf("ocp12360-service-%d", i)
			externalName := fmt.Sprintf("ocp12360-external-name-%d", i)
			output, err := oc.Run("create").Args("service", "externalname", serviceName, "-n", namespace, "--external-name", externalName).Output()
			if i <= limit {
				compat_otp.By(fmt.Sprintf("7.%d) creating service %s, within quota limit, expect success", i, serviceName))
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				compat_otp.By(fmt.Sprintf("7.%d) creating service %s, exceeds quota limit, expect failure", i, serviceName))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("services.*forbidden: exceeded quota"))
			}
		}

		filename = "ocp12360-quota.yaml"
		compat_otp.By(fmt.Sprintf("8) Create multiple quota with resource file %s, expect failure for quota creations that exceed quota limit", filename))
		template = getTestDataFilePath(filename)
		for i := 1; i <= limit+1; i++ {
			quotaName := fmt.Sprintf("ocp12360-quota-%d", i)
			params := []string{"-f", template, "-p", fmt.Sprintf("POD_LIMIT=%d", limits.podLimit), fmt.Sprintf("RQ_LIMIT=%d", limits.resourcequotaLimit), fmt.Sprintf("SECRET_LIMIT=%d", limits.secretLimit), fmt.Sprintf("SERVICE_LIMIT=%d", limits.serviceLimit), fmt.Sprintf("CM_LIMIT=%d", limits.configmapLimit), fmt.Sprintf("NAME=%s", quotaName)}
			configFile := compat_otp.ProcessTemplate(oc, params...)
			output, err := oc.AsAdmin().Run("create").Args("-f", configFile, "-n", namespace).Output()
			if i <= limit {
				compat_otp.By(fmt.Sprintf("8.%d) creating quota %s, within quota limit, expect success", i, quotaName))
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				compat_otp.By(fmt.Sprintf("8.%d) creating quota %s, exceeds quota limit, expect failure", i, quotaName))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("resourcequotas.*forbidden: exceeded quota"))
			}
		}

		compat_otp.By(fmt.Sprintf("9) Create multiple configmaps with resource file %s, expect failure for configmap creations that exceed quota limit", filename))
		for i := 1; i <= limit+1; i++ {
			configmapName := fmt.Sprintf("ocp12360-configmap-%d", i)
			output, err := oc.Run("create").Args("configmap", configmapName, "-n", namespace).Output()
			if i <= limit {
				compat_otp.By(fmt.Sprintf("9.%d) creating configmap %s, within quota limit, expect success", i, configmapName))
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				compat_otp.By(fmt.Sprintf("9.%d) creating configmap %s, exceeds quota limit, expect failure", i, configmapName))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("configmaps.*forbidden: exceeded quota"))
			}
		}
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-16295] User can expose the environment variables to pods [Serial][origin_platformexp_329]", ote.Informing(), func() {
		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		filename := "ocp16295_pod.yaml"
		compat_otp.By(fmt.Sprintf("2) Create pod with resource file %s", filename))
		template := getTestDataFilePath(filename)
		err := oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		podName := "kubernetes-metadata-volume-example"
		compat_otp.By(fmt.Sprintf("3) Wait for pod with name %s ready", podName))
		compat_otp.AssertPodToBeReady(oc, podName, namespace)

		compat_otp.By("4) Check the information in the dump files for pods")
		execOutput, err := oc.Run("exec").Args(podName, "-i", "--", "ls", "-laR", "/data/podinfo-dir").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(execOutput).To(o.ContainSubstring("annotations ->"))
		o.Expect(execOutput).To(o.ContainSubstring("labels ->"))
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-21246] Check the exposed prometheus metrics of operators", ote.Informing(), func() {
		compat_otp.By("1) get serviceaccount token")
		token, err := compat_otp.GetSAToken(oc)
		o.Expect(err).NotTo(o.HaveOccurred())

		resources := []string{"openshift-apiserver-operator", "kube-apiserver-operator", "kube-storage-version-migrator-operator", "kube-controller-manager-operator"}
		patterns := []string{"workqueue_adds", "workqueue_depth", "workqueue_queue_duration", "workqueue_retries", "workqueue_work_duration"}
		step := 2
		for _, resource := range resources {
			compat_otp.By(fmt.Sprintf("%v) For resource %s, check the exposed prometheus metrics", step, resource))

			namespace := resource
			if strings.Contains(resource, "kube-") {
				// need to add openshift prefix for kube resource
				namespace = "openshift-" + resource
			}

			label := "app=" + resource
			compat_otp.By(fmt.Sprintf("%v.1) wait for a pod with label %s to be ready within 15 mins", step, label))
			pods, err := compat_otp.GetAllPodsWithLabel(oc, namespace, label)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(pods).ShouldNot(o.BeEmpty())
			pod := pods[0]
			compat_otp.AssertPodToBeReady(oc, pod, namespace)

			compat_otp.By(fmt.Sprintf("%v.2) request exposed prometheus metrics on pod %s", step, pod))
			command := []string{pod, "-n", namespace, "--", "curl", "--connect-timeout", "30", "--retry", "3", "-N", "-k", "-H", fmt.Sprintf("Authorization: Bearer %v", token), "https://localhost:8443/metrics"}
			output, err := oc.Run("exec").Args(command...).Output()
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By(fmt.Sprintf("%v.3) check the output if it contains the following patterns: %s", step, strings.Join(patterns, ", ")))
			for _, pattern := range patterns {
				o.Expect(output).Should(o.ContainSubstring(pattern))
			}
			// increment step
			step++
		}
	})

	// author: zxiao@redhat.com
	// Longduration/Disruptive: modifies a CRD in-flight and observes watch behavior across the change.
	g.It("[OTP][OCP-24219] Custom resource watchers should terminate instead of hang when its CRD is deleted or modified [Disruptive]", ote.Informing(), func() {
		compat_otp.By("1) Create a new project required for this test execution")
		projectName := fmt.Sprintf("ocp24219-%d", time.Now().UnixNano())
		oc.AsAdmin().Run("new-project").Args(projectName).Execute()
		defer oc.AsAdmin().Run("delete").Args("project", projectName).Execute()
		namespace := projectName

		crdTemplate := getTestDataFilePath("ocp24219-crd.yaml")
		compat_otp.By(fmt.Sprintf("2) Apply custom resource definition from file %s", crdTemplate))
		oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", crdTemplate).Execute()
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", crdTemplate, "--ignore-not-found=true").Execute()
			oc.AsAdmin().WithoutNamespace().Run("wait").Args("--for=delete", "crd/testcrs.example.com", "--timeout=60s").Execute()
		}()

		crTemplate := getTestDataFilePath("ocp24219-cr.yaml")
		compat_otp.By(fmt.Sprintf("3) Apply custom resource from file %s", crTemplate))
		oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", crTemplate, "-n", namespace).Execute()
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-f", crTemplate, "-n", namespace, "--ignore-not-found=true").Execute()

		resourcePath := fmt.Sprintf("/apis/example.com/v1/namespaces/%s/testcrs", namespace)
		compat_otp.By(fmt.Sprintf("4) Start watching custom resource at %s", resourcePath))
		cmd1, backgroundBuf, _, err := oc.AsAdmin().Run("get").Args(fmt.Sprintf("--raw=%s?watch=True", resourcePath), "-n", namespace).Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			cmd1.Process.Kill()
			cmd1.Wait()
		}()
		time.Sleep(5 * time.Second) // wait for watch to start

		compat_otp.By("5) Modify custom resource and apply change")
		crTemplateCopy := CopyToFile(crTemplate, fmt.Sprintf("ocp24219-cr-copy-%d.yaml", time.Now().UnixNano()))
		compat_otp.ModifyYamlFileContent(crTemplateCopy, []compat_otp.YamlReplace{
			{
				Path:  "spec.a",
				Value: "This change to the CR results in a MODIFIED event",
			},
		})
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", crTemplateCopy, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("6) Validate that CR modification event is received")
		o.Eventually(func() bool {
			return strings.Contains(backgroundBuf.String(), "MODIFIED")
		}, 2*time.Minute, 2*time.Second).Should(o.BeTrue(), "MODIFIED event not detected")

		compat_otp.By("7) Modify the CRD and apply change")
		crdTemplateCopy := CopyToFile(crdTemplate, fmt.Sprintf("ocp24219-crd-copy-%d.yaml", time.Now().UnixNano()))
		compat_otp.ModifyYamlFileContent(crdTemplateCopy, []compat_otp.YamlReplace{
			{
				Path:  "spec.versions.0.schema.openAPIV3Schema.properties.spec.properties",
				Value: "b:\n  type: string",
			},
		})
		err = oc.AsAdmin().WithoutNamespace().Run("apply").Args("-f", crdTemplateCopy).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("8) Start a second watch after CRD modification")
		cmd2, backgroundBuf2, _, err := oc.AsAdmin().Run("get").Args(fmt.Sprintf("--raw=%s?watch=True", resourcePath), "-n", namespace).Background()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			cmd2.Process.Kill()
			cmd2.Wait()
		}()
		time.Sleep(5 * time.Second) // allow second watch to start

		crName := "ocp24219-test-cr"
		crdFullName := "crd/testcrs.example.com"
		kind := "OCP24219TestCR"

		compat_otp.By("9) Ensure CR exists before CRD deletion")
		_, err = oc.AsAdmin().WithoutNamespace().Run("get").Args(kind, crName, "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred(), "Expected the CR to exist before deleting CRD")

		compat_otp.By("10) Delete the CRD")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args(crdFullName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("11) Verify CR deletion event after CRD is deleted")
		crDeleteMatchRegex, err := regexp.Compile(`"type":"DELETED".*"object":.*"kind":"` + kind + `"`)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Eventually(func() bool {
			match := crDeleteMatchRegex.MatchString(backgroundBuf2.String())
			if !match {
				e2e.Logf("DEBUG: Buffer after CRD deletion: %s", backgroundBuf2.String())
			}
			return match
		}, 2*time.Minute, 2*time.Second).Should(o.BeTrue(), "CR deletion event not found in watch stream")
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-24698] Check the http accessible /readyz for kube-apiserver [Serial]", ote.Informing(), func() {
		compat_otp.By("1) Check if port 6080 is available")
		err := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 30*time.Second, false, func(cxt context.Context) (bool, error) {
			checkOutput, _ := exec.Command("bash", "-c", "lsof -i:6080").Output()
			// no need to check error since some system output stderr for valid result
			if len(checkOutput) == 0 {
				return true, nil
			}
			e2e.Logf("Port 6080 is occupied, trying again")
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(err, "Port 6080 is available")

		compat_otp.By("2) Get kube-apiserver pods")
		err = oc.AsAdmin().Run("project").Args("openshift-kube-apiserver").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().Run("project").Args("default").Execute() // switch to default project
		podList, err := compat_otp.GetAllPodsWithLabel(oc, "openshift-kube-apiserver", "apiserver")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(podList).ShouldNot(o.BeEmpty())

		compat_otp.By("3) Perform port-forward on the first pod available")
		compat_otp.AssertPodToBeReady(oc, podList[0], "openshift-kube-apiserver")
		_, _, _, err = oc.AsAdmin().Run("port-forward").Args(podList[0], "6080").Background()
		o.Expect(err).NotTo(o.HaveOccurred())

		defer exec.Command("bash", "-c", "kill -HUP $(lsof -t -i:6080)").Output()
		err1 := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 30*time.Second, false, func(cxt context.Context) (bool, error) {
			checkOutput, _ := exec.Command("bash", "-c", "lsof -i:6080").Output()
			// no need to check error since some system output stderr for valid result
			if len(checkOutput) != 0 {
				e2e.Logf("#### Port-forward 6080:6080 is in use")
				return true, nil
			}
			e2e.Logf("#### Waiting for port-forward applying ...")
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(err1, "#### Port-forward 6081:6443 doesn't work")

		compat_otp.By("4) check if port forward succeed")
		checkOutput, err := exec.Command("bash", "-c", "curl http://127.0.0.1:6080/readyz --noproxy \"127.0.0.1\"").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(string(checkOutput)).To(o.Equal("ok"))
		e2e.Logf("Port forwarding works fine")
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-27665] Check if the kube-storage-version-migrator operator related manifests has been loaded", ote.Informing(), func() {
		resource := "customresourcedefinition"
		resourceNames := []string{"storagestates.migration.k8s.io", "storageversionmigrations.migration.k8s.io", "kubestorageversionmigrators.operator.openshift.io"}
		compat_otp.By("1) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "]")
		_, isAvailable := CheckIfResourceAvailable(oc, resource, resourceNames)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "clusteroperators"
		resourceNames = []string{"kube-storage-version-migrator"}
		compat_otp.By("2) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "lease"
		resourceNames = []string{"openshift-kube-storage-version-migrator-operator-lock"}
		namespace := "openshift-kube-storage-version-migrator-operator"
		compat_otp.By("3) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "] under namespace [" + namespace + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "configmap"
		resourceNames = []string{"config"}
		compat_otp.By("4) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "] under namespace [" + namespace + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "service"
		resourceNames = []string{"metrics"}
		compat_otp.By("5) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "serviceaccount"
		resourceNames = []string{"kube-storage-version-migrator-operator"}
		compat_otp.By("6) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "] under namespace [" + namespace + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "deployment"
		resourceNames = []string{"kube-storage-version-migrator-operator"}
		compat_otp.By("7) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "] under namespace [" + namespace + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "serviceaccount"
		resourceNames = []string{"kube-storage-version-migrator-sa"}
		namespace = "openshift-kube-storage-version-migrator"
		compat_otp.By("8) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "] under namespace [" + namespace + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())

		resource = "deployment"
		resourceNames = []string{"migrator"}
		compat_otp.By("9) Check if [" + strings.Join(resourceNames, ", ") + "] is available in [" + resource + "] under namespace [" + namespace + "]")
		_, isAvailable = CheckIfResourceAvailable(oc, resource, resourceNames, namespace)
		o.Expect(isAvailable).Should(o.BeTrue())
	})

	// author: dpunia@redhat.com
	g.It("[OTP][OCP-53085] Test Holes in EndpointSlice Validation Enable Host Network Hijack", ote.Informing(), func() {
		var (
			ns = "tmp53085"
		)

		defer oc.WithoutNamespace().AsAdmin().Run("delete").Args("ns", ns, "--ignore-not-found").Execute()
		err := oc.WithoutNamespace().AsAdmin().Run("create").Args("ns", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("1) Check Holes in EndpointSlice Validation Enable Host Network Hijack")
		endpointSliceConfig := getTestDataFilePath("endpointslice.yaml")
		sliceCreateOut, sliceCreateError := oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", ns, "-f", endpointSliceConfig).Output()
		o.Expect(sliceCreateOut).Should(o.ContainSubstring(`Invalid value: "127.0.0.1": may not be in the loopback range`))
		o.Expect(sliceCreateError).To(o.HaveOccurred())
	})

	// author: dpunia@redhat.com
	g.It("[OTP][OCP-53229] Test Arbitrary path injection via type field in CNI configuration [Apiserver]", ote.Informing(), func() {
		compat_otp.By("1) Create new project")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By("2) Create NetworkAttachmentDefinition with name nefarious-conf using nefarious.yaml")
		nefariousConfTemplate := getTestDataFilePath("ocp53229-nefarious.yaml")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-n", namespace, "-f", nefariousConfTemplate).Execute()
		nefariousConfErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", namespace, "-f", nefariousConfTemplate).Execute()
		o.Expect(nefariousConfErr).NotTo(o.HaveOccurred())

		compat_otp.By("3) Create Pod by using created NetworkAttachmentDefinition in annotations")
		nefariousPodTemplate := getTestDataFilePath("ocp53229-nefarious-pod.yaml")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-n", namespace, "-f", nefariousPodTemplate).Execute()
		nefariousPodErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", namespace, "-f", nefariousPodTemplate).Execute()
		o.Expect(nefariousPodErr).NotTo(o.HaveOccurred())

		compat_otp.By("4) Check pod should be in creating or failed status and event should show error message invalid plugin")
		podStatus, podErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, "-f", nefariousPodTemplate, "-o", "jsonpath={.status.phase}").Output()
		o.Expect(podErr).NotTo(o.HaveOccurred())
		o.Expect(podStatus).ShouldNot(o.ContainSubstring("Running"))

		err := wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 2*time.Minute, false, func(cxt context.Context) (bool, error) {
			podEvent, podEventErr := oc.AsAdmin().WithoutNamespace().Run("describe").Args("-n", namespace, "-f", nefariousPodTemplate).Output()
			o.Expect(podEventErr).NotTo(o.HaveOccurred())
			matched, _ := regexp.MatchString("error adding pod.*to CNI network.*invalid plugin name: ../../../../usr/sbin/reboot", podEvent)
			if matched {
				e2e.Logf("Step 4. Test Passed")
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(err, "Detected event CNI network invalid plugin")

		compat_otp.By("5) Check pod created on node should not be rebooting and appear offline")
		nodeName, nodeErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, "-f", nefariousPodTemplate, "-o", "jsonpath={.spec.nodeName}").Output()
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		nodeStatus, nodeStatusErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "--no-headers").Output()
		o.Expect(nodeStatusErr).NotTo(o.HaveOccurred())
		o.Expect(nodeStatus).Should(o.ContainSubstring("Ready"))
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-11476] oadm new-project should fail when invalid node selector is given [origin_infrastructure_392]", ote.Informing(), func() {
		compat_otp.By("1) Create projects with an invalid node-selector (neither equality-based nor set-based)")
		projectName := compat_otp.RandStrCustomize("abcdefghijklmnopqrstuvwxyz", 5)
		invalidNodeSelectors := []string{"env:qa", "env,qa", "env [qa]", "env,"}

		for _, invalidNodeSelector := range invalidNodeSelectors {
			compat_otp.By(fmt.Sprintf("2) Create project %s with node selector %s, expect failure", projectName, invalidNodeSelector))
			output, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("new-project", projectName, fmt.Sprintf("--node-selector=%s", invalidNodeSelector)).Output()
			o.Expect(err).To(o.HaveOccurred())

			compat_otp.By("3) Assert error message is in expected format")
			invalidOutputRegex := fmt.Sprintf("Invalid value.*%s", regexp.QuoteMeta(invalidNodeSelector))
			o.Expect(output).To(o.MatchRegexp(invalidOutputRegex))
		}
	})

	// author: dpunia@redhat.com
	g.It("[OTP][OCP-11887] Could delete all the resource when deleting the project [Serial]", ote.Informing(), func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		compat_otp.By("1) Create a project")
		projectName := "project-11887"
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", projectName, "--ignore-not-found").Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("new-project").Args(projectName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2) Create new app")
		err = oc.AsAdmin().WithoutNamespace().Run("new-app").Args("--name=hello-openshift", "quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83", "-n", projectName, "--import-mode=PreserveOriginal").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) Build hello-world from external source")
		helloWorldSource := "quay.io/openshifttest/ruby-27:1.2.0~https://github.com/openshift/ruby-hello-world"
		imageError := oc.Run("new-build").Args(helloWorldSource, "--name=ocp-11887-test-"+strings.ToLower(compat_otp.RandStr(5)), "-n", projectName, "--import-mode=PreserveOriginal").Execute()
		if imageError != nil {
			if !isConnectedInternet(oc) {
				e2e.Failf("Failed to access to the internet, something wrong with the connectivity of the cluster! Please check!")
			}
		}

		compat_otp.By("4) Get project resource")
		for _, resource := range []string{"buildConfig", "deployments", "pods", "services"} {
			out := getResourceToBeReady(oc, asAdmin, withoutNamespace, resource, "-n", projectName, "-o=jsonpath={.items[*].metadata.name}")
			o.Expect(len(out)).To(o.BeNumerically(">", 0))
		}

		compat_otp.By("5) Delete the project")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", projectName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("5.1) Check project is deleted")
		err = wait.PollUntilContextTimeout(context.Background(), 20*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			out, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("project", projectName).Output()
			if matched, _ := regexp.MatchString("namespaces .* not found", out); matched {
				e2e.Logf("Step 5.1. Test Passed, project is deleted")
				return true, nil
			}
			e2e.Logf("Project delete is in progress :: %s", out)
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(err, "Step 5.1. Test Failed, Project is not deleted")

		compat_otp.By("6) Get project resource after project is deleted")
		out, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", projectName, "all", "--no-headers").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(out).Should(o.ContainSubstring("No resources found"))

		compat_otp.By("7) Create a project with same name, no context for this new one")
		err = oc.AsAdmin().WithoutNamespace().Run("new-project").Args(projectName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		out, err = oc.AsAdmin().WithoutNamespace().Run("status").Args("-n", projectName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(out).Should(o.ContainSubstring("no services, deployment"))
	})

	// author: kewang@redhat.com
	// Slow/Serial: replaces the cluster's project-request template, which triggers an openshift-apiserver rollout.
	g.It("[OTP][OCP-12308] Customizing template for project creation [Serial][Slow]", ote.Informing(), func() {
		var (
			caseID           = "ocp-12308"
			dirname          = "/tmp/-ocp-12308"
			templateYaml     = "template.yaml"
			templateYamlFile = filepath.Join(dirname, templateYaml)
			patchYamlFile    = filepath.Join(dirname, "patch.yaml")
			project1         = caseID + "-test1"
			project2         = caseID + "-test2"
			patchJSON        = `[{"op": "replace", "path": "/spec/projectRequestTemplate", "value":{"name":"project-request"}}]`
			restorePatchJSON = `[{"op": "replace", "path": "/spec", "value" :{}}]`
			initRegExpr      = []string{`limits.cpu[\s]+0[\s]+6`, `limits.memory[\s]+0[\s]+16Gi`, `pods[\s]+0[\s]+10`, `requests.cpu[\s]+0[\s]+4`, `requests.memory[\s]+0[\s]+8Gi`}
			regexpr          = []string{`limits.cpu[\s]+[1-9]+[\s]+6`, `limits.memory[\s]+[A-Za-z0-9]+[\s]+16Gi`, `pods[\s]+[1-9]+[\s]+10`, `requests.cpu[\s]+[A-Za-z0-9]+[\s]+4`, `requests.memory[\s]+[A-Za-z0-9]+[\s]+8Gi`}
		)

		err := os.MkdirAll(dirname, 0755)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(dirname)

		compat_otp.By("1) Create a bootstrap project template and output it to a file template.yaml")
		_, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("create-bootstrap-project-template", "-o", "yaml").OutputToFile(filepath.Join(caseID, templateYaml))
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2) To customize template.yaml and add ResourceQuota and LimitRange objects.")
		patchYaml := `- apiVersion: v1
  kind: "LimitRange"
  metadata:
    name: ${PROJECT_NAME}-limits
  spec:
    limits:
      - type: "Container"
        default:
          cpu: "1"
          memory: "1Gi"
        defaultRequest:
          cpu: "500m"
          memory: "500Mi"
- apiVersion: v1
  kind: ResourceQuota
  metadata:
    name: ${PROJECT_NAME}-quota
  spec:
    hard:
      pods: "10"
      requests.cpu: "4"
      requests.memory: 8Gi
      limits.cpu: "6"
      limits.memory: 16Gi
      requests.storage: "20G"
`
		f, _ := os.Create(patchYamlFile)
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = fmt.Fprintf(w, "%s", patchYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Insert the patch Yaml before the keyword 'parameters:' in template yaml file
		sedCmd := fmt.Sprintf(`sed -i '/^parameters:/e cat %s' %s`, patchYamlFile, templateYamlFile)
		e2e.Logf("Check sed cmd %s description:", sedCmd)
		_, err = exec.Command("bash", "-c", sedCmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) Create a project request template from the customized template.yaml file in the openshift-config namespace.")
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", templateYamlFile, "-n", "openshift-config").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("templates", "project-request", "-n", "openshift-config").Execute()

		compat_otp.By("4) Create new project before applying the customized template of projects.")
		err = oc.AsAdmin().WithoutNamespace().Run("new-project").Args(project1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", project1).Execute()

		compat_otp.By("5) Associate the template with projectRequestTemplate in the project resource of the config.openshift.io/v1.")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("project.config.openshift.io/cluster", "--type=json", "-p", patchJSON).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("patch").Args("project.config.openshift.io/cluster", "--type=json", "-p", restorePatchJSON).Execute()
			expectedStatus := map[string]string{"Progressing": "True"}
			err = waitCoBecomes(oc, "openshift-apiserver", 240, expectedStatus)
			compat_otp.AssertWaitPollNoErr(err, `openshift-apiserver status has not yet changed to {"Progressing": "True"} in 240 seconds`)
			expectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
			err = waitCoBecomes(oc, "openshift-apiserver", 360, expectedStatus)
			compat_otp.AssertWaitPollNoErr(err, `openshift-apiserver operator status has not yet changed to {"Available": "True", "Progressing": "False", "Degraded": "False"} in 360 seconds`)
			e2e.Logf("openshift-apiserver pods are all running.")
		}()

		compat_otp.By("5.1) Wait until the openshift-apiserver clusteroperator complete degradation and in the normal status ...")
		// It needs a bit more time to wait for all openshift-apiservers getting back to normal.
		expectedStatus := map[string]string{"Progressing": "True"}
		err = waitCoBecomes(oc, "openshift-apiserver", 240, expectedStatus)
		compat_otp.AssertWaitPollNoErr(err, `openshift-apiserver status has not yet changed to {"Progressing": "True"} in 240 seconds`)
		expectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
		err = waitCoBecomes(oc, "openshift-apiserver", 360, expectedStatus)
		compat_otp.AssertWaitPollNoErr(err, `openshift-apiserver operator status has not yet changed to {"Available": "True", "Progressing": "False", "Degraded": "False"} in 360 seconds`)
		e2e.Logf("openshift-apiserver operator is normal and pods are all running.")

		compat_otp.By("6) The resource quotas will be used for a new project after the customized template of projects is applied.")
		err = oc.AsAdmin().WithoutNamespace().Run("new-project").Args(project2).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", project2).Execute()

		output, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", project2).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Check quotas setting of project %s description:", project2)
		o.Expect(string(output)).To(o.ContainSubstring(project2 + "-quota"))
		for _, regx := range initRegExpr {
			o.Expect(string(output)).Should(o.MatchRegexp(regx))
		}

		compat_otp.By("7) To add applications to created project, check if Quota usage of the project is changed.")
		err = oc.AsAdmin().WithoutNamespace().Run("new-app").Args("quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83", "--import-mode=PreserveOriginal").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Waiting for all pods of hello-openshift application to be ready ...")
		err = wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err := oc.WithoutNamespace().Run("get").Args("pods", "--no-headers").Output()
			if err != nil {
				e2e.Logf("Failed to get pods' status of project %s, error: %s. Trying again", project2, err)
				return false, nil
			}
			if matched, _ := regexp.MatchString(`(ContainerCreating|Init|Pending)`, output); matched {
				e2e.Logf("Some of pods still not get ready:\n%s", output)
				return false, nil
			}
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(err, "Some of pods still not get ready!")

		output, err = oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", project2).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Check quotas changes of project %s after new app is created:", project2)
		for _, regx := range regexpr {
			o.Expect(string(output)).Should(o.MatchRegexp(regx))
		}

		compat_otp.By("8) Check the previously created project, no quotas setting is applied.")
		output, err = oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", project1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Check quotas changes of project %s after new app is created:", project1)
		o.Expect(string(output)).NotTo(o.ContainSubstring(project1 + "-quota"))
		o.Expect(string(output)).NotTo(o.ContainSubstring(project1 + "-limits"))
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-12158] Specify ResourceQuota on project [Apiserver]", ote.Informing(), func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig") && isEnabledCapability(oc, "ImageRegistry")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		var (
			imageLimitRangeYamlFile = tmpdir + "image-limit-range.yaml"
			imageName1              = `quay.io/openshifttest/base-alpine@sha256:3126e4eed4a3ebd8bf972b2453fa838200988ee07c01b2251e3ea47e4b1f245c`
			imageName2              = `quay.io/openshifttest/hello-openshift:1.2.0`
			imageName3              = `quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83`
			imageStreamErr          error
		)

		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()
		defer oc.AsAdmin().Run("delete").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()

		imageLimitRangeYaml := `apiVersion: v1
kind: ResourceQuota
metadata:
   name: openshift-object-counts
spec:
   hard:
      openshift.io/imagestreams: "1"
`

		compat_otp.By("2) Create a resource quota limit of the imagestream with limit 1")
		f, err := os.Create(imageLimitRangeYamlFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = w.WriteString(imageLimitRangeYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		quotaErr := oc.AsAdmin().Run("create").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
		o.Expect(quotaErr).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("3.) Applying a mystream:v1 image tag to %s in an image stream should succeed", imageName1))
		tagErr := oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName1, "--source=docker", "mystream:v1", "-n", namespace).Execute()
		o.Expect(tagErr).NotTo(o.HaveOccurred())

		// Inline steps will wait for tag 1 to get it imported successfully before adding tag 2 and this helps to avoid race-caused failure.Ref:OCPQE-7679.
		errImage := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			imageStreamOutput, imageStreamErr := oc.AsAdmin().WithoutNamespace().Run("describe").Args("imagestream", "mystream", "-n", namespace).Output()
			if imageStreamErr == nil {
				if strings.Contains(imageStreamOutput, imageName1) {
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(errImage, fmt.Sprintf("Image tagging with v1 is not successful %s", imageStreamErr))

		compat_otp.By(fmt.Sprintf("4.) Applying the mystream2:v1 image tag to another %s in an image stream should fail due to the ImageStream max limit", imageName2))
		output, tagErr := oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName2, "--source=docker", "mystream2:v1", "-n", namespace).Output()
		o.Expect(tagErr).To(o.HaveOccurred())
		o.Expect(string(output)).To(o.MatchRegexp("forbidden: [Ee]xceeded quota"))

		compat_otp.By(`5.) Copying an image to the default internal registry of the cluster should be denied due to the max imagestream limit for images`)
		destRegistry := "docker://" + defaultRegistryServiceURL + "/" + namespace + "/mystream3"
		publicImageUrl := "docker://" + imageName3
		errPoll := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err = copyImageToInternelRegistry(oc, namespace, publicImageUrl, destRegistry)
			if err != nil {
				if strings.Contains(output, "denied") {
					o.Expect(strings.Contains(output, "denied")).Should(o.BeTrue(), "Should deny copying"+publicImageUrl)
					return true, nil
				}
			}
			return false, nil
		})
		if errPoll != nil {
			e2e.Logf("Failed to retrieve %v", output)
			compat_otp.AssertWaitPollNoErr(errPoll, "Failed to retrieve")
		}
	})

	// author: dpunia@redhat.com
	g.It("[OTP][OCP-12193] User can get node selector from a project", ote.Informing(), func() {
		var (
			caseID        = "ocp-12193"
			firstProject  = "e2e-apiserver-first" + caseID + "-" + compat_otp.GetRandomString()
			secondProject = "e2e-apiserver-second" + caseID + "-" + compat_otp.GetRandomString()
			labelValue    = "qa" + compat_otp.GetRandomString()
		)
		oc.SetupProject()
		userName := oc.Username()

		compat_otp.By("Pre-requisities, capturing current-context from cluster.")
		origContxt, contxtErr := oc.Run("config").Args("current-context").Output()
		o.Expect(contxtErr).NotTo(o.HaveOccurred())
		defer func() {
			useContxtErr := oc.Run("config").Args("use-context", origContxt).Execute()
			o.Expect(useContxtErr).NotTo(o.HaveOccurred())
		}()

		compat_otp.By("1) Create a project without node selector")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", firstProject).Execute()
		err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("new-project", firstProject, "--admin="+userName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("2) Create a project with node selector")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", secondProject).Execute()
		err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("new-project", secondProject, "--node-selector=env="+labelValue, "--description=testnodeselector", "--admin="+userName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) Check node selector field for above 2 projects")
		firstProjectOut, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", firstProject, "--as="+userName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(firstProjectOut).Should(o.MatchRegexp("Node Selector:.*<none>"))

		secondProjectOut, err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", secondProject, "--as="+userName).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(secondProjectOut).Should(o.MatchRegexp("Node Selector:.*env=" + labelValue))
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-12263] When exceed openshift.io/images will ban to create image reference or push image to project [Apiserver]", ote.Informing(), func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig") && isEnabledCapability(oc, "ImageRegistry")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		var (
			imageLimitRangeYamlFile = tmpdir + "image-limit-range.yaml"
			imageName1              = `quay.io/openshifttest/base-alpine@sha256:3126e4eed4a3ebd8bf972b2453fa838200988ee07c01b2251e3ea47e4b1f245c`
			imageName2              = `quay.io/openshifttest/hello-openshift:1.2.0`
			imageName3              = `quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83`
			imageStreamErr          error
		)

		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()
		defer oc.AsAdmin().Run("delete").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()

		imageLimitRangeYaml := `apiVersion: v1
kind: LimitRange
metadata:
  name: openshift-resource-limits
spec:
  limits:
    - type: openshift.io/Image
      max:
        storage: 1Gi
    - type: openshift.io/ImageStream
      max:
        openshift.io/image-tags: 20
        openshift.io/images: 1
`

		compat_otp.By("2) Create a resource quota limit of the image with images limit 1")
		f, err := os.Create(imageLimitRangeYamlFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = w.WriteString(imageLimitRangeYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		quotaErr := oc.AsAdmin().Run("create").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
		o.Expect(quotaErr).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("3.) Applying a mystream:v1 image tag to %s in an image stream should succeed", imageName1))
		tagErr := oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName1, "--source=docker", "mystream:v1", "-n", namespace).Execute()
		o.Expect(tagErr).NotTo(o.HaveOccurred())

		// Inline steps will wait for tag 1 to get it imported successfully before adding tag 2 and this helps to avoid race-caused failure.Ref:OCPQE-7679.
		errImage := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			imageStreamOutput, imageStreamErr := oc.AsAdmin().WithoutNamespace().Run("describe").Args("imagestream", "mystream", "-n", namespace).Output()
			if imageStreamErr == nil {
				if strings.Contains(imageStreamOutput, imageName1) {
					e2e.Logf("Image is tag with v1 successfully\n%s", imageStreamOutput)
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(errImage, fmt.Sprintf("Image is tag with v1 is not successfull %s", imageStreamErr))

		compat_otp.By(fmt.Sprintf("4.) Applying the mystream:v2 image tag to another %s in an image stream should fail due to the ImageStream max images limit", imageName2))
		tagErr = oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName2, "--source=docker", "mystream:v2", "-n", namespace).Execute()
		o.Expect(tagErr).NotTo(o.HaveOccurred())

		var imageStreamv2Err error
		errImageV2 := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			imageStreamv2Output, imageStreamv2Err := oc.AsAdmin().WithoutNamespace().Run("describe").Args("imagestream", "mystream", "-n", namespace).Output()
			if imageStreamv2Err == nil {
				if strings.Contains(imageStreamv2Output, "Import failed") {
					e2e.Logf("Image is tag with v2 not successfull\n%s", imageStreamv2Output)
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(errImageV2, fmt.Sprintf("Image is tag with v2 is successfull %s", imageStreamv2Err))

		compat_otp.By(`5.) Copying an image to the default internal registry of the cluster should be denied due to the max storage size limit for images`)
		destRegistry := "docker://" + defaultRegistryServiceURL + "/" + namespace + "/mystream:latest"
		publicImageUrl := "docker://" + imageName3
		var output string
		errPoll := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err = copyImageToInternelRegistry(oc, namespace, publicImageUrl, destRegistry)
			if err != nil {
				if strings.Contains(output, "denied") {
					o.Expect(strings.Contains(output, "denied")).Should(o.BeTrue(), "Should deny copying"+publicImageUrl)
					return true, nil
				}
			}
			return false, nil
		})
		if errPoll != nil {
			e2e.Logf("Failed to retrieve %v", output)
			compat_otp.AssertWaitPollNoErr(errPoll, "Failed to retrieve")
		}
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-22565] Check if the given user or group have the privilege via SubjectAccessReview [origin_platformexp_214][REST]", ote.Informing(), func() {
		isExternalOIDCCluster, err := compat_otp.IsExternalOIDCCluster(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		if isExternalOIDCCluster {
			g.Skip("Skipping the test as we are running against an external OIDC cluster.")
		}

		compat_otp.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()
		username := oc.Username()

		// helper function for executing post request to SubjectAccessReview
		postSubjectAccessReview := func(username string, namespace string, step string, expectStatus string) {
			compat_otp.By(fmt.Sprintf("%s>>) Get base URL for API requests", step))
			baseURL, err := oc.Run("whoami").Args("--show-server").Output()
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By(fmt.Sprintf("%s>>) Get access token", step))
			token, err := oc.Run("whoami").Args("-t").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			authHeader := fmt.Sprintf(`Authorization: Bearer %s`, token)

			compat_otp.By(fmt.Sprintf("%s>>) Submit POST request to API SubjectAccessReview", step))
			url := baseURL + filepath.Join("/apis/authorization.openshift.io/v1/namespaces", namespace, "localsubjectaccessreviews")
			e2e.Logf("Get post SubjectAccessReview REST API server %s", url)

			postMap := map[string]string{
				"kind":       "LocalSubjectAccessReview",
				"apiVersion": "authorization.openshift.io/v1",
				"verb":       "create",
				"resource":   "pods",
				"user":       username,
			}
			postJSON, err := json.Marshal(postMap)
			o.Expect(err).NotTo(o.HaveOccurred())

			command := fmt.Sprintf("curl -X POST %s -w '%s' -o /dev/null -k -H '%s' -H 'Content-Type: application/json' -d '%s'", url, "%{http_code}", authHeader, string(postJSON))
			postSubjectAccessReviewStatus, err := exec.Command("bash", "-c", command).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(string(postSubjectAccessReviewStatus)).To(o.Equal(expectStatus))
		}

		// setup role for user and post to API
		testUserAccess := func(role string, step string, expectStatus string) {
			compat_otp.By(fmt.Sprintf("%s>>) Remove default role [admin] from the current user [%s]", step, username))
			errAdmRole := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 30*time.Second, false, func(cxt context.Context) (bool, error) {
				rolebindingOutput, _ := oc.AsAdmin().WithoutNamespace().Run("get").Args("rolebinding/admin", "-n", namespace, "--no-headers", "-oname").Output()
				if rolebindingOutput == "rolebinding.rbac.authorization.k8s.io/admin" {
					policyerr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "remove-role-from-user", "admin", username, "-n", namespace).Execute()
					if policyerr != nil {
						return false, nil
					}
				}
				return true, nil
			})
			rolebindingOutput, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("rolebinding", "-n", namespace).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			e2e.Logf("Rolebinding of user %v :: %v", username, rolebindingOutput)
			compat_otp.AssertWaitPollNoErr(errAdmRole, fmt.Sprintf("Not able to delete admin role for user :: %v :: %v", username, errAdmRole))

			compat_otp.By(fmt.Sprintf("%s>>) Add new role [%s] to the current user [%s]", step, role, username))
			err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-role-to-user", role, username, "-n", namespace).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			compat_otp.By(fmt.Sprintf("%s>>) POST to SubjectAccessReview API for user %s under namespace %s, expect status %s", step, username, namespace, expectStatus))
			postSubjectAccessReview(username, namespace, step, expectStatus)
		}

		compat_otp.By("2) Test user access with role [view], expect failure")
		testUserAccess("view", "2", "403")

		compat_otp.By("3) Test user access with role [edit], expect failure")
		testUserAccess("edit", "3", "403")

		compat_otp.By("4) Test user access with role [admin], expect success")
		testUserAccess("admin", "4", "201")
	})

	// author: dpunia@redhat.com
	// Longduration/Disruptive: applies an invalid apiserver CR config, then patches to a valid one and waits for kube-apiserver to roll out.
	g.It("[OTP][OCP-24389] Verify the CR admission of the APIServer CRD [Slow][Disruptive]", ote.Informing(), func() {
		var (
			patchOut        string
			patchJsonRevert = `{"spec": {"additionalCORSAllowedOrigins": null}}`
			patchJson       = `{
			"spec": {
				"additionalCORSAllowedOrigins": [
				"(?i)//127\\.0\\.0\\.1(:|\\z)",
				"(?i)//localhost(:|\\z)",
				"(?i)//kubernetes\\.default(:|\\z)",
				"(?i)//kubernetes\\.default\\.svc\\.cluster\\.local(:|\\z)",
				"(?i)//kubernetes(:|\\z)",
				"(?i)//openshift\\.default(:|\\z)",
				"(?i)//openshift\\.default\\.svc(:|\\z)",
				"(?i)//openshift\\.default\\.svc\\.cluster\\.local(:|\\z)",
				"(?i)//kubernetes\\.default\\.svc(:|\\z)",
				"(?i)//openshift(:|\\z)"
			]}}`
		)

		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		apiServerRecover := func() {
			errKASO := waitCoBecomes(oc, "kube-apiserver", 100, map[string]string{"Progressing": "True"})
			compat_otp.AssertWaitPollNoErr(errKASO, "kube-apiserver operator is not start progressing in 100 seconds")
			e2e.Logf("Checking kube-apiserver operator should be Available in 1500 seconds")
			errKASO = waitCoBecomes(oc, "kube-apiserver", 1500, map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"})
			compat_otp.AssertWaitPollNoErr(errKASO, "openshift-kube-apiserver pods revisions recovery not completed")
		}

		defer func() {
			if strings.Contains(patchOut, "patched") {
				err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("apiserver", "cluster", "--type=merge", "-p", patchJsonRevert).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
				// Wait for kube-apiserver recover
				apiServerRecover()
			}
		}()

		compat_otp.By("1) Update apiserver config(additionalCORSAllowedOrigins) with invalid config `no closing (parentheses`")
		patch := `{"spec": {"additionalCORSAllowedOrigins": ["no closing (parentheses"]}}`
		patchOut, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("apiserver", "cluster", "--type=merge", "-p", patch).Output()
		o.Expect(err).Should(o.HaveOccurred())
		o.Expect(patchOut).Should(o.ContainSubstring(`"no closing (parentheses": not a valid regular expression`))

		compat_otp.By("2) Update apiserver config(additionalCORSAllowedOrigins) with invalid string type")
		patch = `{"spec": {"additionalCORSAllowedOrigins": "some string"}}`
		patchOut, err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("apiserver", "cluster", "--type=merge", "-p", patch).Output()
		o.Expect(err).Should(o.HaveOccurred())
		o.Expect(patchOut).Should(o.ContainSubstring(`body must be of type array: "string"`))

		compat_otp.By("3) Update apiserver config(additionalCORSAllowedOrigins) with valid config")
		patchOut, err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("apiserver", "cluster", "--type=merge", "-p", patchJson).Output()
		o.Expect(err).ShouldNot(o.HaveOccurred())
		o.Expect(patchOut).Should(o.ContainSubstring("patched"))
		// Wait for kube-apiserver recover
		apiServerRecover()

		compat_otp.By("4) Verifying the additionalCORSAllowedOrigins by inspecting the HTTP response headers")
		urlStr, err := oc.Run("whoami").Args("--show-server").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		req, err := http.NewRequest("GET", urlStr, nil)
		o.Expect(err).NotTo(o.HaveOccurred())
		req.Header.Set("Origin", "http://localhost")

		tr := &http.Transport{}
		if os.Getenv("HTTPS_PROXY") != "" || os.Getenv("https_proxy") != "" {
			httpsProxyURL, err := url.Parse(os.Getenv("https_proxy"))
			o.Expect(err).NotTo(o.HaveOccurred())
			tr.Proxy = http.ProxyURL(httpsProxyURL)
		}
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := &http.Client{
			Transport: tr,
			Timeout:   time.Second * 30,
		}

		resp, err := client.Do(req)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer resp.Body.Close()
		o.Expect(resp.Header.Get("Access-Control-Allow-Origin")).To(o.Equal("http://localhost"))
	})

	// author: kewang@redhat.com
	// Disruptive: applies a non-existent secret reference for API namedCertificates and verifies the kube-apiserver operator degrades gracefully without rolling pods.
	g.It("[OTP][OCP-65924] Specifying non-existent secret for API namedCertificates renders inconsistent config [Disruptive]", ote.Informing(), func() {
		// Currently, there is one bug OCPBUGS-15853 on 4.13, after the related PRs are merged, consider back-porting the case to 4.13
		var (
			apiserver           = "apiserver/cluster"
			kas                 = "openshift-kube-apiserver"
			kasOpExpectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
			kasOpNewStatus      = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "True"}
			apiServerFQDN, _    = getApiServerFQDNandPort(oc, false)
			patch               = fmt.Sprintf(`{"spec":{"servingCerts": {"namedCertificates": [{"names": ["%s"], "servingCertificate": {"name": "client-ca-cusom"}}]}}}`, apiServerFQDN)
			patchToRecover      = `[{ "op": "remove", "path": "/spec/servingCerts" }]`
		)

		defer func() {
			compat_otp.By(" Last) Check the kube-apiserver cluster operator after removed the non-existen secret for API namedCertificates .")
			err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(apiserver, "-p", patchToRecover, "--type=json").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			err = waitCoBecomes(oc, "kube-apiserver", 300, kasOpExpectedStatus)
			compat_otp.AssertWaitPollNoErr(err, "kube-apiserver operator is not becomes available")
		}()

		compat_otp.By("1) Get the current revision of openshift-kube-apiserver.")
		out, revisionChkErr := oc.AsAdmin().Run("get").Args("po", "-n", kas, "-l=apiserver", "-o", "jsonpath={.items[*].metadata.labels.revision}").Output()
		o.Expect(revisionChkErr).NotTo(o.HaveOccurred())
		s := strings.Split(out, " ")
		preRevisionSum := 0
		for _, valueStr := range s {
			valueInt, _ := strconv.Atoi(valueStr)
			preRevisionSum += valueInt
		}
		e2e.Logf("Current revisions of kube-apiservers: %v", out)

		compat_otp.By("2) Apply non-existent secret for API namedCertificates.")
		err := oc.AsAdmin().WithoutNamespace().Run("patch").Args(apiserver, "-p", patch, "--type=merge").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) Wait for a while and check the status of kube-apiserver cluster operator.")
		errCo := waitCoBecomes(oc, "kube-apiserver", 300, kasOpNewStatus)
		compat_otp.AssertWaitPollNoErr(errCo, "kube-apiserver operator is not becomes degraded")
		output, err := oc.AsAdmin().WithoutNamespace().Run("get").Args("co", "kube-apiserver").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("ConfigObservationDegraded"))

		compat_otp.By("4) Check that cluster does nothing and no kube-server pod crash-looping.")
		out, revisionChkErr = oc.AsAdmin().Run("get").Args("po", "-n", kas, "-l=apiserver", "-o", "jsonpath={.items[*].metadata.labels.revision}").Output()
		o.Expect(revisionChkErr).NotTo(o.HaveOccurred())
		s1 := strings.Split(out, " ")
		postRevisionSum := 0
		for _, valueStr := range s1 {
			valueInt, _ := strconv.Atoi(valueStr)
			postRevisionSum += valueInt
		}
		e2e.Logf("Revisions of kube-apiservers after patching: %v", out)
		o.Expect(postRevisionSum).Should(o.BeNumerically("==", preRevisionSum), "Validation failed as PostRevision value not equal to PreRevision")
		e2e.Logf("No changes on revisions of kube-apiservers.")

		kasPodsOutput := getResourceToBeReady(oc, asAdmin, withoutNamespace, "pods", "-l apiserver", "--no-headers", "-n", kas)
		o.Expect(kasPodsOutput).ShouldNot(o.ContainSubstring("CrashLoopBackOff"))
		e2e.Logf("Kube-apiservers didn't roll out as expected.")
	})

	// author: jmekkatt@redhat.com
	g.It("[OTP][OCP-50188] An informational error on kube-apiserver in case an admission webhook is installed for a virtual resource [Serial]", ote.Informing(), func() {
		var (
			validatingWebhookName = "test-validating-cfg"
			mutatingWebhookName   = "test-mutating-cfg"
			validatingWebhook     = getTestDataFilePath("ValidatingWebhookConfigurationTemplate.yaml")
			mutatingWebhook       = getTestDataFilePath("MutatingWebhookConfigurationTemplate.yaml")
			kubeApiserverCoStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
			serviceName           = "testservice"
			serviceNamespace      = "testnamespace"
			reason                = "AdmissionWebhookMatchesVirtualResource"
		)

		compat_otp.By("Pre-requisities step : Create new namespace for the tests.")
		oc.SetupProject()

		validatingWebHook := admissionWebhook{
			name:             validatingWebhookName,
			webhookname:      "test.validating.com",
			servicenamespace: serviceNamespace,
			servicename:      serviceName,
			namespace:        oc.Namespace(),
			apigroups:        "authorization.k8s.io",
			apiversions:      "v1",
			operations:       "*",
			resources:        "subjectaccessreviews",
			template:         validatingWebhook,
		}

		mutatingWebHook := admissionWebhook{
			name:             mutatingWebhookName,
			webhookname:      "test.mutating.com",
			servicenamespace: serviceNamespace,
			servicename:      serviceName,
			namespace:        oc.Namespace(),
			apigroups:        "authorization.k8s.io",
			apiversions:      "v1",
			operations:       "*",
			resources:        "subjectaccessreviews",
			template:         mutatingWebhook,
		}

		compat_otp.By("1) Create a ValidatingWebhookConfiguration with virtual resource reference.")
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("delete").Args("ValidatingWebhookConfiguration", validatingWebhookName, "--ignore-not-found").Execute()
		}()
		preConfigKasStatus := getCoStatus(oc, "kube-apiserver", kubeApiserverCoStatus)
		validatingWebHook.createAdmissionWebhookFromTemplate(oc)
		_, isAvailable := CheckIfResourceAvailable(oc, "ValidatingWebhookConfiguration", []string{validatingWebhookName}, "")
		o.Expect(isAvailable).Should(o.BeTrue())
		e2e.Logf("Test step-1 has passed : Creation of ValidatingWebhookConfiguration with virtual resource reference succeeded.")

		compat_otp.By("2) Check for kube-apiserver operator status after virtual resource reference for a validating webhook added.")
		kasOperatorCheckForStep(oc, preConfigKasStatus, "2", "virtual resource reference for a validating webhook added")
		e2e.Logf("Test step-2 has passed : Kube-apiserver operator are in normal after virtual resource reference for a validating webhook added.")

		compat_otp.By("3) Check for information message on kube-apiserver cluster w.r.t virtual resource reference for a validating webhook")
		compareAPIServerWebhookConditions(oc, reason, "True", []string{`VirtualResourceAdmissionError`})
		validatingDelErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("ValidatingWebhookConfiguration", validatingWebhookName).Execute()
		o.Expect(validatingDelErr).NotTo(o.HaveOccurred())
		e2e.Logf("Test step-3 has passed : Kube-apiserver reports expected informational errors after virtual resource reference for a validating webhook added.")

		compat_otp.By("4) Create a MutatingWebhookConfiguration with a virtual resource reference.")
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("delete").Args("MutatingWebhookConfiguration", mutatingWebhookName, "--ignore-not-found").Execute()
		}()
		preConfigKasStatus = getCoStatus(oc, "kube-apiserver", kubeApiserverCoStatus)
		mutatingWebHook.createAdmissionWebhookFromTemplate(oc)
		_, isAvailable = CheckIfResourceAvailable(oc, "MutatingWebhookConfiguration", []string{mutatingWebhookName}, "")
		o.Expect(isAvailable).Should(o.BeTrue())
		e2e.Logf("Test step-4 has passed : Creation of MutatingWebhookConfiguration with virtual resource reference succeeded.")

		compat_otp.By("5) Check for kube-apiserver operator status after virtual resource reference for a Mutating webhook added.")
		kasOperatorCheckForStep(oc, preConfigKasStatus, "5", "virtual resource reference for a Mutating webhook added")
		e2e.Logf("Test step-5 has passed : Kube-apiserver operators are in normal after virtual resource reference for a mutating webhook added.")

		compat_otp.By("6) Check for information message on kube-apiserver cluster w.r.t virtual resource reference for mutating webhook")
		compareAPIServerWebhookConditions(oc, reason, "True", []string{`VirtualResourceAdmissionError`})
		preConfigKasStatus = getCoStatus(oc, "kube-apiserver", kubeApiserverCoStatus)
		mutatingDelErr := oc.AsAdmin().WithoutNamespace().Run("delete").Args("MutatingWebhookConfiguration", mutatingWebhookName).Execute()
		o.Expect(mutatingDelErr).NotTo(o.HaveOccurred())
		e2e.Logf("Test step-6 has passed : Kube-apiserver reports expected informational errors after deleting webhooks.")

		compat_otp.By("7) Check for webhook admission error free kube-apiserver cluster after deleting webhooks.")
		compareAPIServerWebhookConditions(oc, "", "False", []string{`VirtualResourceAdmissionError`})
		kasOperatorCheckForStep(oc, preConfigKasStatus, "7", "deleting webhooks")
		e2e.Logf("Test step-7 has passed : No webhook admission error seen after purging webhooks.")
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-56934] Ensure unique CA serial numbers after enable automated service CA rotation [Apiserver]", ote.Informing(), func() {
		var (
			dirname = "/tmp/-OCP-56934/"
		)

		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		defer os.RemoveAll(dirname)
		err := os.MkdirAll(dirname, 0755)
		o.Expect(err).NotTo(o.HaveOccurred())

		e2e.Logf("Cluster should be healthy before running case.")
		err = clusterHealthcheck(oc, "OCP-56934/log")
		if err == nil {
			e2e.Logf("Cluster health check passed before running case")
		} else {
			g.Skip(fmt.Sprintf("Cluster health check failed before running case :: %s ", err))
		}

		compat_otp.By("1. Get openshift-apiserver pods and endpoints ip & port")
		podName, podGetErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", "openshift-apiserver", "pod", "--field-selector=status.phase=Running", "-o", "jsonpath={.items[0].metadata.name}").Output()
		o.Expect(podGetErr).NotTo(o.HaveOccurred())
		endpointIP, epGetErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", "openshift-apiserver", "endpoints", "api", "-o", fmt.Sprintf(`jsonpath={.subsets[*].addresses[?(@.targetRef.name=="%v")].ip}`, podName)).Output()
		o.Expect(epGetErr).NotTo(o.HaveOccurred())

		compat_otp.By("2. Check openshift-apiserver https api metrics endpoint URL")
		err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			metricsUrl := fmt.Sprintf(`https://%v:8443/metrics`, string(endpointIP))
			metricsOut, metricsErr := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-apiserver", podName, "-c", "openshift-apiserver", "--", "curl", "-k", "--connect-timeout", "5", "--retry", "2", "-N", "-s", metricsUrl).Output()
			if metricsErr == nil {
				o.Expect(metricsOut).ShouldNot(o.ContainSubstring("You are attempting to import a cert with the same issuer/serial as an existing cert, but that is not the same cert"))
				o.Expect(metricsOut).Should(o.ContainSubstring("Forbidden"))
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(err, "Test Failed")
	})

	// author: kewang@redhat.com
	g.It("[OTP][OCP-57243] Viewing audit logs [Apiserver]", ote.Informing(), func() {
		var (
			apiservers    = []string{"openshift-apiserver", "kube-apiserver", "oauth-apiserver"}
			caseID        = "OCP-57243"
			dirname       = "/tmp/-" + caseID
			mustgatherDir = dirname + "/must-gather.ocp-57243"
		)

		defer os.RemoveAll(dirname)

		err := os.MkdirAll(dirname, 0o755)
		o.Expect(err).NotTo(o.HaveOccurred())
		err = os.MkdirAll(mustgatherDir, 0o755)
		o.Expect(err).NotTo(o.HaveOccurred())
		masterNode, masterErr := compat_otp.GetFirstMasterNode(oc)
		o.Expect(masterErr).NotTo(o.HaveOccurred())
		e2e.Logf("Master node is %v : ", masterNode)

		for i, apiserver := range apiservers {
			compat_otp.By(fmt.Sprintf("%d.1)View the %s audit logs are available for each control plane node:", i+1, apiserver))
			output, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", "--role=master", "--path="+apiserver+"/").Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(output).Should(o.MatchRegexp(".*audit.log"))
			e2e.Logf("The OpenShift API server audit logs are available for each control plane node:\n%s", output)

			compat_otp.By(fmt.Sprintf("%d.2) View a specific %s audit log by providing the node name and the log name:", i+1, apiserver))
			auditLogFile := fmt.Sprintf("%s-audit.log", apiserver)
			auditLogPath, err1 := oc.AsAdmin().WithoutNamespace().Run("adm").Args("node-logs", masterNode, "--path="+apiserver+"/audit.log").OutputToFile(auditLogFile)
			o.Expect(err1).NotTo(o.HaveOccurred())
			cmd := fmt.Sprintf(`tail -1 %v`, auditLogPath)
			cmdOut, cmdErr := exec.Command("bash", "-c", cmd).Output()
			o.Expect(cmdErr).NotTo(o.HaveOccurred())
			e2e.Logf("An example of %s audit log:\n%s", apiserver, cmdOut)
		}

		compat_otp.By("4) Gathering audit logs to run the oc adm must-gather command and view the audit log files:")
		_, mgErr := oc.AsAdmin().WithoutNamespace().Run("adm").Args("must-gather", "--dest-dir="+mustgatherDir, "--", "/usr/bin/gather_audit_logs").Output()
		o.Expect(mgErr).NotTo(o.HaveOccurred())
		cmd := fmt.Sprintf(`du -h %v`, mustgatherDir)
		cmdOut, cmdErr := exec.Command("bash", "-c", cmd).Output()
		o.Expect(cmdErr).NotTo(o.HaveOccurred())
		e2e.Logf("View the audit log files for running the oc adm must-gather command:\n%s", cmdOut)
		// Verify that the main API server audit logs are not empty.
		// Note: etcd audit logs may not be available in all configurations.
		for _, apiserver := range apiservers {
			cmd = fmt.Sprintf(`du -h %v | grep 'audit_logs/%s'`, mustgatherDir, apiserver)
			apiServerOut, apiServerErr := exec.Command("bash", "-c", cmd).Output()
			o.Expect(apiServerErr).NotTo(o.HaveOccurred())
			o.Expect(apiServerOut).ShouldNot(o.ContainSubstring("0B"), fmt.Sprintf("%s audit logs should not be empty", apiserver))
		}
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-11531] Can access both http and https pods and services via the API proxy [Serial]", ote.Informing(), func() {
		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		// Case is failing on which cluster dns is not resolvable ...
		apiServerFQDN, _ := getApiServerFQDNandPort(oc, false)
		cmd := fmt.Sprintf(`nslookup %s`, apiServerFQDN)
		nsOutput, nsErr := exec.Command("bash", "-c", cmd).Output()
		if nsErr != nil {
			g.Skip(fmt.Sprintf("DNS resolution failed, case is not suitable for environment %s :: %s", nsOutput, nsErr))
		}

		compat_otp.By("1) Create a new project required for this test execution")
		oc.SetupProject()
		projectNs := oc.Namespace()

		compat_otp.By("2. Get the clustername")
		clusterName, clusterErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("view", "-o", `jsonpath={.clusters[0].name}`).Output()
		o.Expect(clusterErr).NotTo(o.HaveOccurred())
		e2e.Logf("Cluster Name :: %v", clusterName)

		compat_otp.By("3. Point to the API server referring the cluster name")
		apiserverName, apiErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("view", "-o", `jsonpath={.clusters[?(@.name=="`+clusterName+`")].cluster.server}`).Output()
		o.Expect(apiErr).NotTo(o.HaveOccurred())
		e2e.Logf("Server Name :: %v", apiserverName)

		compat_otp.By("4) Get access token")
		token, err := oc.Run("whoami").Args("-t").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		// Define the URL values
		urls := []struct {
			URL       string
			Target    string
			ExpectStr string
		}{
			{
				URL:       "quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83",
				Target:    "hello-openshift",
				ExpectStr: "Hello OpenShift!",
			},
			{
				URL:       "quay.io/openshifttest/nginx-alpine@sha256:f78c5a93df8690a5a937a6803ef4554f5b6b1ef7af4f19a441383b8976304b4c",
				Target:    "nginx-alpine",
				ExpectStr: "Hello-OpenShift nginx",
			},
		}

		for i, u := range urls {
			compat_otp.By(fmt.Sprintf("%d.1) Build "+u.Target+" from external source", i+5))
			appErr := oc.AsAdmin().WithoutNamespace().Run("new-app").Args(u.URL, "-n", projectNs, "--import-mode=PreserveOriginal").Execute()
			o.Expect(appErr).NotTo(o.HaveOccurred())

			compat_otp.By(fmt.Sprintf("%d.2) Check if pod is properly running with expected status.", i+5))
			podsList := getPodsListByLabel(oc.AsAdmin(), projectNs, "deployment="+u.Target)
			compat_otp.AssertPodToBeReady(oc, podsList[0], projectNs)

			compat_otp.By(fmt.Sprintf("%d.3) Perform the proxy GET request to resource REST endpoint with service", i+5))
			curlUrl := fmt.Sprintf(`%s/api/v1/namespaces/%s/services/http:%s:8080-tcp/proxy/`, apiserverName, projectNs, u.Target)
			output := clientCurl(token, curlUrl)
			o.Expect(output).Should(o.ContainSubstring(u.ExpectStr))

			compat_otp.By(fmt.Sprintf("%d.4) Perform the proxy GET request to resource REST endpoint with pod", i+5))
			curlUrl = fmt.Sprintf(`%s/api/v1/namespaces/%s/pods/http:%s:8080/proxy`, apiserverName, projectNs, podsList[0])
			output = clientCurl(token, curlUrl)
			o.Expect(output).Should(o.ContainSubstring(u.ExpectStr))
		}
	})

	// author: zxiao@redhat.com
	g.It("[OTP][OCP-33830] customize audit config of apiservers negative test [Serial]", ote.Informing(), func() {
		var (
			namespace = "openshift-kube-apiserver"
			label     = fmt.Sprintf("app=%s", namespace)
			pod       string
		)

		compat_otp.By(fmt.Sprintf("1) Wait for a pod with the label %s to show up", label))
		err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			pods, err := compat_otp.GetAllPodsWithLabel(oc, namespace, label)
			if err != nil || len(pods) == 0 {
				e2e.Logf("Fail to get pod, error: %s. Trying again", err)
				return false, nil
			}
			pod = pods[0]
			e2e.Logf("Got pod with name:%s", pod)
			return true, nil
		})
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("Cannot find pod with label %s", label))

		compat_otp.By(fmt.Sprintf("2) Record number of revisions of apiserver pod with name %s before test", pod))
		beforeRevision, err := oc.AsAdmin().Run("get").Args("pod", pod, "-o=jsonpath={.metadata.labels.revision}", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		apiserver := "apiserver/cluster"
		compat_otp.By(fmt.Sprintf("3) Set invalid audit profile name to %s, expect failure", apiserver))
		output, err := oc.AsAdmin().Run("patch").Args(apiserver, "-p", `{"spec": {"audit": {"profile": "myprofile"}}}`, "--type=merge", "-n", namespace).Output()
		o.Expect(err).To(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(`Unsupported value: "myprofile"`))

		compat_otp.By(fmt.Sprintf("4) Set valid empty patch to %s, expect success", apiserver))
		output, err = oc.AsAdmin().Run("patch").Args(apiserver, "-p", `{"spec": {}}`, "--type=merge", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).To(o.ContainSubstring(`cluster patched (no change)`))

		compat_otp.By(fmt.Sprintf("5) Try to delete %s, expect failure", apiserver))
		err = oc.AsAdmin().Run("delete").Args(apiserver, "-n", namespace).Execute()
		o.Expect(err).To(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("6) Compare number of revisions of apiserver pod with name %s to the one before test, expect unchanged", pod))
		afterRevision, err := oc.AsAdmin().Run("get").Args("pod", pod, "-o=jsonpath={.metadata.labels.revision}", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(afterRevision).To(o.Equal(beforeRevision))
	})

	// author: xxia@redhat.com
	// Disruptive: forces etcd encryption key rotation via unsupportedConfigOverrides; causes a kube-apiserver rollout.
	g.It("[OTP][OCP-25806] Force encryption key rotation for etcd datastore [Slow][Disruptive]", ote.Informing(), func() {
		// only run this case in Etcd Encryption On cluster
		compat_otp.By("1.) Check if cluster is Etcd Encryption On")
		encryptionType, err := oc.WithoutNamespace().Run("get").Args("apiserver/cluster", "-o=jsonpath={.spec.encryption.type}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if encryptionType != "aescbc" && encryptionType != "aesgcm" {
			g.Skip("The cluster is Etcd Encryption Off, this case intentionally runs nothing")
		}
		e2e.Logf("Etcd Encryption with type %s is on!", encryptionType)

		compat_otp.By("2. Get encryption prefix")
		oasEncValPrefix1, err := GetEncryptionPrefix(oc, "/openshift.io/routes")
		compat_otp.AssertWaitPollNoErr(err, "fail to get encryption prefix for key routes ")
		e2e.Logf("openshift-apiserver resource encrypted value prefix before test is %s", oasEncValPrefix1)

		kasEncValPrefix1, err1 := GetEncryptionPrefix(oc, "/kubernetes.io/secrets")
		compat_otp.AssertWaitPollNoErr(err1, "fail to get encryption prefix for key secrets ")
		e2e.Logf("kube-apiserver resource encrypted value prefix before test is %s", kasEncValPrefix1)

		oasEncNumber, err2 := GetEncryptionKeyNumber(oc, `encryption-key-openshift-apiserver-[^ ]*`)
		o.Expect(err2).NotTo(o.HaveOccurred())
		kasEncNumber, err3 := GetEncryptionKeyNumber(oc, `encryption-key-openshift-kube-apiserver-[^ ]*`)
		o.Expect(err3).NotTo(o.HaveOccurred())

		t := time.Now().Format(time.RFC3339)
		patchYamlToRestore := `[{"op":"replace","path":"/spec/unsupportedConfigOverrides","value":null}]`
		// Below cannot use the patch format "op":"replace" due to it is uncertain
		// whether it is `unsupportedConfigOverrides: null`
		// or the unsupportedConfigOverrides is not existent
		patchYaml := `
spec:
  unsupportedConfigOverrides:
    encryption:
      reason: force OAS rotation ` + t
		for i, kind := range []string{"openshiftapiserver", "kubeapiserver"} {
			defer func() {
				e2e.Logf("Restoring %s/cluster's spec", kind)
				err := oc.WithoutNamespace().Run("patch").Args(kind, "cluster", "--type=json", "-p", patchYamlToRestore).Execute()
				o.Expect(err).NotTo(o.HaveOccurred())
			}()
			compat_otp.By(fmt.Sprintf("3.%d) Forcing %s encryption", i+1, kind))
			err := oc.WithoutNamespace().Run("patch").Args(kind, "cluster", "--type=merge", "-p", patchYaml).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		newOASEncSecretName := "encryption-key-openshift-apiserver-" + strconv.Itoa(oasEncNumber+1)
		newKASEncSecretName := "encryption-key-openshift-kube-apiserver-" + strconv.Itoa(kasEncNumber+1)

		compat_otp.By("4. Check the new encryption key secrets appear")
		errKey := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err := oc.WithoutNamespace().Run("get").Args("secrets", newOASEncSecretName, newKASEncSecretName, "-n", "openshift-config-managed").Output()
			if err != nil {
				e2e.Logf("Fail to get new encryption key secrets, error: %s. Trying again", err)
				return false, nil
			}
			e2e.Logf("Got new encryption key secrets:\n%s", output)
			return true, nil
		})
		// Print openshift-apiserver and kube-apiserver secrets for debugging if time out
		errOAS := oc.WithoutNamespace().Run("get").Args("secret", "-n", "openshift-config-managed", "-l", `encryption.apiserver.operator.openshift.io/component=openshift-apiserver`).Execute()
		o.Expect(errOAS).NotTo(o.HaveOccurred())
		errKAS := oc.WithoutNamespace().Run("get").Args("secret", "-n", "openshift-config-managed", "-l", `encryption.apiserver.operator.openshift.io/component=openshift-kube-apiserver`).Execute()
		o.Expect(errKAS).NotTo(o.HaveOccurred())
		compat_otp.AssertWaitPollNoErr(errKey, fmt.Sprintf("new encryption key secrets %s, %s not found", newOASEncSecretName, newKASEncSecretName))

		compat_otp.By("5. Waiting for the force encryption completion")
		// Only need to check kubeapiserver because kubeapiserver takes more time.
		var completed bool
		completed, err = WaitEncryptionKeyMigration(oc, newKASEncSecretName)
		compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("saw all migrated-resources for %s", newKASEncSecretName))
		o.Expect(completed).Should(o.Equal(true))

		var oasEncValPrefix2, kasEncValPrefix2 string
		compat_otp.By("6. Get encryption prefix after force encryption completed")
		oasEncValPrefix2, err = GetEncryptionPrefix(oc, "/openshift.io/routes")
		compat_otp.AssertWaitPollNoErr(err, "fail to get encryption prefix for key routes ")
		e2e.Logf("openshift-apiserver resource encrypted value prefix after test is %s", oasEncValPrefix2)

		kasEncValPrefix2, err = GetEncryptionPrefix(oc, "/kubernetes.io/secrets")
		compat_otp.AssertWaitPollNoErr(err, "fail to get encryption prefix for key secrets ")
		e2e.Logf("kube-apiserver resource encrypted value prefix after test is %s", kasEncValPrefix2)

		o.Expect(oasEncValPrefix2).Should(o.ContainSubstring(fmt.Sprintf("k8s:enc:%s:v1", encryptionType)))
		o.Expect(kasEncValPrefix2).Should(o.ContainSubstring(fmt.Sprintf("k8s:enc:%s:v1", encryptionType)))
		o.Expect(oasEncValPrefix2).NotTo(o.Equal(oasEncValPrefix1))
		o.Expect(kasEncValPrefix2).NotTo(o.Equal(kasEncValPrefix1))
	})

	// author: rgangwar@redhat.com
	// Disruptive/Slow: changes the cluster-wide audit profile twice, each causing a kube-apiserver rollout, then restores Default.
	g.It("[OTP][OCP-33427] customize audit config of apiservers [Disruptive][Slow]", ote.Informing(), func() {
		var (
			patchAllRequestBodies   = `[{"op": "replace", "path": "/spec/audit", "value":{"profile":"AllRequestBodies"}}]`
			patchWriteRequestBodies = `[{"op": "replace", "path": "/spec/audit", "value":{"profile":"WriteRequestBodies"}}]`
			patchToRecover          = `[{"op": "replace", "path": "/spec/audit", "value":{"profile":"Default"}}]`
			podScript               = "grep -r '\"managedFields\":{' /var/log/kube-apiserver | wc -l"
			now                     = time.Now().UTC()
			unixTimestamp           = now.Unix()
		)

		defer func() {
			compat_otp.By("Restoring apiserver/cluster's profile")
			output := setAuditProfile(oc, "apiserver/cluster", patchToRecover)
			if strings.Contains(output, "patched (no change)") {
				e2e.Logf("Apiserver/cluster's audit profile not changed from the default values")
			}
		}()

		compat_otp.By("1. Checking the current default audit policy of cluster")
		checkApiserversAuditPolicies(oc, "Default")

		compat_otp.By("2. Get all master nodes.")
		masterNodes, getAllMasterNodesErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(getAllMasterNodesErr).NotTo(o.HaveOccurred())
		o.Expect(masterNodes).NotTo(o.BeEmpty())

		compat_otp.By("3. Checking verbs in kube-apiserver audit logs")
		script := fmt.Sprintf(`grep -hE "\"verb\":\"(create|delete|patch|update)\",\"user\":.*(requestObject|responseObject)|\"verb\":\"(get|list|watch)\",\"user\":.*(requestObject|responseObject)" /var/log/kube-apiserver/audit.log | jq -r "select (.requestReceivedTimestamp | .[0:19] + \"Z\" | fromdateiso8601 > %v)" | tail -n 1`, unixTimestamp)
		masterNodeLogs, errCount := checkAuditLogs(oc, script, masterNodes[0], "openshift-kube-apiserver")
		if errCount > 0 {
			e2e.Failf("Verbs in kube-apiserver audit logs on master node %v :: %v", masterNodes[0], masterNodeLogs)
		}
		e2e.Logf("No verbs logs in kube-apiserver audit logs on master node %v", masterNodes[0])
		compat_otp.By("4. Set audit profile to WriteRequestBodies")
		setAuditProfile(oc, "apiserver/cluster", patchWriteRequestBodies)

		compat_otp.By("5. Checking the current WriteRequestBodies audit policy of cluster.")
		checkApiserversAuditPolicies(oc, "WriteRequestBodies")

		compat_otp.By("6. Checking verbs and managedFields in kube-apiserver audit logs after audit profile to WriteRequestBodies")
		masterNodeLogs, errCount = checkAuditLogs(oc, script, masterNodes[0], "openshift-kube-apiserver")
		if errCount == 0 {
			e2e.Failf("Post audit profile to WriteRequestBodies, No Verbs in kube-apiserver audit logs on master node %v :: %v :: %v", masterNodes[0], masterNodeLogs, errCount)
		}

		podsList := getPodsListByLabel(oc.AsAdmin(), "openshift-kube-apiserver", "app=openshift-kube-apiserver")
		execKasOuptut := ExecCommandOnPod(oc, podsList[0], "openshift-kube-apiserver", podScript)
		trimOutput := strings.TrimSpace(execKasOuptut)
		count, _ := strconv.Atoi(trimOutput)
		if count == 0 {
			e2e.Logf("The step succeeded and the managedFields count is zero in KAS logs.")
		} else {
			e2e.Failf("The step Failed and the managedFields count is not zero in KAS logs :: %d.", count)
		}
		e2e.Logf("Post audit profile to WriteRequestBodies, verbs captured in kube-apiserver audit logs on master node %v", masterNodes[0])

		compat_otp.By("7. Set audit profile to AllRequestBodies")
		setAuditProfile(oc, "apiserver/cluster", patchAllRequestBodies)

		compat_otp.By("8. Checking the current AllRequestBodies audit policy of cluster.")
		checkApiserversAuditPolicies(oc, "AllRequestBodies")

		compat_otp.By("9. Checking verbs and managedFields in kube-apiserver audit logs after audit profile to AllRequestBodies")
		masterNodeLogs, errCount = checkAuditLogs(oc, script, masterNodes[0], "openshift-kube-apiserver")
		if errCount == 0 {
			e2e.Failf("Post audit profile to AllRequestBodies, No Verbs in kube-apiserver audit logs on master node %v :: %v", masterNodes[0], masterNodeLogs)
		}

		execKasOuptut = ExecCommandOnPod(oc, podsList[0], "openshift-kube-apiserver", podScript)
		trimOutput = strings.TrimSpace(execKasOuptut)
		count, _ = strconv.Atoi(trimOutput)
		if count == 0 {
			e2e.Logf("The step succeeded and the managedFields count is zero in KAS logs.")
		} else {
			e2e.Failf("The step Failed and the managedFields count is not zero in KAS logs :: %d.", count)
		}
		e2e.Logf("Post audit profile to AllRequestBodies, Verbs captured in kube-apiserver audit logs on master node %v", masterNodes[0])
	})

	// author: kewang@redhat.com
	g.It("[OTP][OCP-11289] Check the imagestreams of quota in the project after build image [ConnectedOnly][Serial]", ote.Informing(), func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		var (
			caseID                  = "ocp-11289"
			dirname                 = "/tmp/-" + caseID
			ocpObjectCountsYamlFile = dirname + "openshift-object-counts.yaml"
			expectedQuota           = "openshift.io/imagestreams:2"
		)
		compat_otp.By("1) Create a new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By("2) Create a ResourceQuota count of image stream")
		ocpObjectCountsYaml := `apiVersion: v1
kind: ResourceQuota
metadata:
  name: openshift-object-counts
spec:
  hard:
    openshift.io/imagestreams: "10"
`
		f, err := os.Create(ocpObjectCountsYamlFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = fmt.Fprintf(w, "%s", ocpObjectCountsYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		defer oc.AsAdmin().Run("delete").Args("-f", ocpObjectCountsYamlFile, "-n", namespace).Execute()
		quotaErr := oc.AsAdmin().Run("create").Args("-f", ocpObjectCountsYamlFile, "-n", namespace).Execute()
		o.Expect(quotaErr).NotTo(o.HaveOccurred())

		compat_otp.By("3. Checking the created Resource Quota of the Image Stream")
		quota := getResourceToBeReady(oc, asAdmin, withoutNamespace, "quota", "openshift-object-counts", `--template={{.status.used}}`, "-n", namespace)
		o.Expect(quota).Should(o.ContainSubstring("openshift.io/imagestreams:0"), "openshift-object-counts")

		checkImageStreamQuota := func(buildName string, step string) {
			buildErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 90*time.Second, false, func(cxt context.Context) (bool, error) {
				bs := getResourceToBeReady(oc, asAdmin, withoutNamespace, "builds", buildName, "-ojsonpath={.status.phase}", "-n", namespace)
				if strings.Contains(bs, "Complete") {
					e2e.Logf("Building of %s status:%v", buildName, bs)
					return true, nil
				}
				e2e.Logf("Building of %s is still not complete, continue to monitor ...", buildName)
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(buildErr, fmt.Sprintf("ERROR: Build status of %s is not complete!", buildName))

			compat_otp.By(fmt.Sprintf("%s.1 Checking the created Resource Quota of the Image Stream", step))
			quota := getResourceToBeReady(oc, asAdmin, withoutNamespace, "quota", "openshift-object-counts", `--template={{.status.used}}`, "-n", namespace)

			if !strings.Contains(quota, expectedQuota) {
				out, _ := getResource(oc, asAdmin, withoutNamespace, "imagestream", "-n", namespace)
				e2e.Logf("imagestream are used: %s", out)
				e2e.Failf("expected quota openshift-object-counts %s doesn't match the reality %s! Please check!", expectedQuota, quota)
			}
		}

		compat_otp.By("4. Create a source build using source code and check the build info")
		imgErr := oc.AsAdmin().WithoutNamespace().Run("new-build").Args(`quay.io/openshifttest/ruby-27:1.2.0~https://github.com/sclorg/ruby-ex.git`, "-n", namespace, "--import-mode=PreserveOriginal").Execute()
		if imgErr != nil {
			if !isConnectedInternet(oc) {
				e2e.Failf("Failed to access to the internet, something wrong with the connectivity of the cluster! Please check!")
			}
		}
		o.Expect(imgErr).NotTo(o.HaveOccurred())
		checkImageStreamQuota("ruby-ex-1", "4")

		compat_otp.By("5. Starts a new build for the provided build config")
		sbErr := oc.AsAdmin().WithoutNamespace().Run("start-build").Args("ruby-ex", "-n", namespace).Execute()
		o.Expect(sbErr).NotTo(o.HaveOccurred())
		checkImageStreamQuota("ruby-ex-2", "5")
	})

	// author: dpunia@redhat.com
	// SNO-only: injects kube-apiserver installer pod rollout failures to verify no fall-backoff when latestAvailableRevision > targetRevision.
	g.It("[OTP][OCP-44738] The installer pod fall-backoff should not happen if latestAvailableRevision > targetRevision [Disruptive]", ote.Informing(), func() {
		if !isSNOCluster(oc) {
			g.Skip("This is not a SNO cluster, skip.")
		}

		defer func() {
			compat_otp.By("4) Change Step 1 injection by updating unsupportedConfigOverrides to null")
			patch := `[{"op": "replace", "path": "/spec/unsupportedConfigOverrides", "value": null}]`
			rollOutError := oc.AsAdmin().WithoutNamespace().Run("patch").Args("kubeapiserver/cluster", "--type=json", "-p", patch).Execute()
			o.Expect(rollOutError).NotTo(o.HaveOccurred())

			compat_otp.By("5) Performed apiserver force rollout to test step 4 changes.")
			patch = fmt.Sprintf(`[ {"op": "replace", "path": "/spec/forceRedeploymentReason", "value": "Force Redploy %v" } ]`, time.Now().UnixNano())
			patchForceRedploymentError := oc.AsAdmin().WithoutNamespace().Run("patch").Args("kubeapiserver/cluster", "--type=json", "-p", patch).Execute()
			o.Expect(patchForceRedploymentError).NotTo(o.HaveOccurred())

			compat_otp.By("6) Check latestAvailableRevision > targetRevision")
			rollOutError = wait.PollUntilContextTimeout(context.Background(), 60*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
				targetRevisionOut, revisionGetErr := oc.WithoutNamespace().Run("get").Args("kubeapiserver/cluster", "-o", "jsonpath={.status.nodeStatuses[*].targetRevision}").Output()
				o.Expect(revisionGetErr).NotTo(o.HaveOccurred())
				targetRevision, _ := strconv.Atoi(targetRevisionOut)

				latestAvailableRevisionOut, latestrevisionGetErr := oc.WithoutNamespace().Run("get").Args("kubeapiserver/cluster", "-o", "jsonpath={.status.latestAvailableRevision}").Output()
				o.Expect(latestrevisionGetErr).NotTo(o.HaveOccurred())
				latestAvailableRevision, _ := strconv.Atoi(latestAvailableRevisionOut)

				if latestAvailableRevision > targetRevision {
					e2e.Logf("Step 6, Test Passed: latestAvailableRevision > targetRevision")
					return true, nil
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(rollOutError, "Step 6, Test Failed: latestAvailableRevision > targetRevision and rollout is not affected")

			compat_otp.By("7) Check Kube-apiserver operator Roll Out Successfully & rollout is not affected")
			rollOutError = wait.PollUntilContextTimeout(context.Background(), 60*time.Second, 900*time.Second, false, func(cxt context.Context) (bool, error) {
				operatorOutput, operatorChkError := oc.WithoutNamespace().Run("get").Args("co/kube-apiserver").Output()
				if operatorChkError == nil {
					matched, _ := regexp.MatchString("True.*False.*False", operatorOutput)
					if matched {
						e2e.Logf("Kube-apiserver operator Roll Out Successfully & rollout is not affected")
						e2e.Logf("Step 7, Test Passed")
						return true, nil
					}
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(rollOutError, "Step 7, Test Failed: Kube-apiserver operator failed to Roll Out")
		}()

		compat_otp.By("1) Set the installer pods to fail and try backoff during rollout by injecting error")
		patch := `[{"op": "replace", "path": "/spec/unsupportedConfigOverrides", "value": {"installerErrorInjection":{"failPropability":1.0}}}]`
		patchConfigError := oc.AsAdmin().WithoutNamespace().Run("patch").Args("kubeapiserver/cluster", "--type=json", "-p", patch).Execute()
		o.Expect(patchConfigError).NotTo(o.HaveOccurred())

		compat_otp.By("2) Performed apiserver force rollout to test step 1 changes.")
		patch = fmt.Sprintf(`[ {"op": "replace", "path": "/spec/forceRedeploymentReason", "value": "Force Redploy %v" } ]`, time.Now().UnixNano())
		patchForceRedploymentError := oc.AsAdmin().WithoutNamespace().Run("patch").Args("kubeapiserver/cluster", "--type=json", "-p", patch).Execute()
		o.Expect(patchForceRedploymentError).NotTo(o.HaveOccurred())

		compat_otp.By("3) Check apiserver created retry installer pods with error and retrying backoff")
		fallbackError := wait.PollUntilContextTimeout(context.Background(), 60*time.Second, 600*time.Second, false, func(cxt context.Context) (bool, error) {
			targetRevision, revisionGetErr := oc.WithoutNamespace().Run("get").Args("kubeapiserver/cluster", "-o", "jsonpath={.status.nodeStatuses[*].targetRevision}").Output()
			o.Expect(revisionGetErr).NotTo(o.HaveOccurred())

			// Check apiserver installer pod is failing with retry error
			installerPod, installerPodErr := oc.WithoutNamespace().Run("get").Args("po", "-n", "openshift-kube-apiserver", "-l", "app=installer").Output()
			o.Expect(installerPodErr).NotTo(o.HaveOccurred())
			cmd := fmt.Sprintf("echo '%v' | grep 'Error' | grep -c 'installer-%v-retry' || true", installerPod, targetRevision)
			retryPodOutput, retryPodChkerr := exec.Command("bash", "-c", cmd).Output()
			o.Expect(retryPodChkerr).NotTo(o.HaveOccurred())

			retryPodCount, strConvError := strconv.Atoi(strings.Trim(string(retryPodOutput), "\n"))
			o.Expect(strConvError).NotTo(o.HaveOccurred())
			if retryPodCount > 0 {
				e2e.Logf("Step 3, Test Passed: Got retry error installer pod")
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(fallbackError, "Step 3, Test Failed: Failed to get retry error installer pod")
	})

	// author: rgangwar@redhat.com
	// Disruptive/Slow: sets audit profile to None, causing a kube-apiserver rollout, then restores Default.
	g.It("[OTP][OCP-43261] APIServer Support None audit policy [Disruptive][Slow]", ote.Informing(), func() {
		var (
			patch                = `[{"op": "replace", "path": "/spec/audit", "value":{"profile":"None"}}]`
			patchToRecover       = `[{"op": "replace", "path": "/spec/audit", "value":{"profile":"Default"}}]`
			expectedProgCoStatus = map[string]string{"Progressing": "True"}
			expectedCoStatus     = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
			coOps                = []string{"authentication", "openshift-apiserver"}
		)

		defer func() {
			contextErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("use-context", "admin").Execute()
			o.Expect(contextErr).NotTo(o.HaveOccurred())
			contextOutput, contextErr := oc.AsAdmin().WithoutNamespace().Run("whoami").Args("--show-context").Output()
			o.Expect(contextErr).NotTo(o.HaveOccurred())
			e2e.Logf("Context after rollback :: %v", contextOutput)
		}()

		defer func() {
			compat_otp.By("Restoring apiserver/cluster's profile")
			output, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("apiserver/cluster", "--type=json", "-p", patchToRecover).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			if strings.Contains(output, "patched (no change)") {
				e2e.Logf("Apiserver/cluster's audit profile not changed from the default values")
			} else {
				compat_otp.By("Checking KAS, OAS, Auththentication operators should be in Progressing and Available after rollout and recovery")
				e2e.Logf("Checking kube-apiserver operator should be in Progressing in 100 seconds")
				err = waitCoBecomes(oc, "kube-apiserver", 100, expectedProgCoStatus)
				compat_otp.AssertWaitPollNoErr(err, "kube-apiserver operator is not start progressing in 100 seconds")
				e2e.Logf("Checking kube-apiserver operator should be Available in 1500 seconds")
				err = waitCoBecomes(oc, "kube-apiserver", 1500, expectedCoStatus)
				compat_otp.AssertWaitPollNoErr(err, "kube-apiserver operator is not becomes available in 1500 seconds")

				// Using 60s because KAS takes long time, when KAS finished rotation, OAS and Auth should have already finished.
				for _, ops := range coOps {
					e2e.Logf("Checking %s should be Available in 60 seconds", ops)
					err = waitCoBecomes(oc, ops, 60, expectedCoStatus)
					compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("%v operator is not becomes available in 60 seconds", ops))
				}
			}
		}()

		compat_otp.By("1. Set None profile to audit log")
		output, err := oc.AsAdmin().WithoutNamespace().Run("patch").Args("apiserver/cluster", "--type=json", "-p", patch).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring("patched"), "apiserver/cluster not patched")
		compat_otp.By("2. Checking KAS, OAS, Auththentication operators should be in Progressing and Available after rollout and recovery")
		compat_otp.By("2.1 Checking kube-apiserver operator should be in Progressing in 100 seconds")
		err = waitCoBecomes(oc, "kube-apiserver", 100, expectedProgCoStatus)
		compat_otp.AssertWaitPollNoErr(err, "kube-apiserver operator is not start progressing in 100 seconds")
		compat_otp.By("2.2 Checking kube-apiserver operator should be Available in 1500 seconds")
		err = waitCoBecomes(oc, "kube-apiserver", 1500, expectedCoStatus)
		compat_otp.AssertWaitPollNoErr(err, "kube-apiserver operator is not becomes available in 1500 seconds")

		// Using 60s because KAS takes long time, when KAS finished rotation, OAS and Auth should have already finished.
		i := 3
		for _, ops := range coOps {
			compat_otp.By(fmt.Sprintf("2.%d Checking %s should be Available in 60 seconds", i, ops))
			err = waitCoBecomes(oc, ops, 60, expectedCoStatus)
			compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("%v operator is not becomes available in 60 seconds", ops))
			i = i + 1
		}
		e2e.Logf("KAS, OAS and Auth operator are available after rollout")

		// Must-gather for audit logs
		// Related bug 2008223
		// Due to bug 2040654, exit code is unable to get failure exit code from executed script, so the step will succeed here.
		compat_otp.By("3. Get must-gather audit logs")
		msg, err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("must-gather", "--dest-dir=/"+tmpdir+"/audit_must_gather_OCP-43261", "--", "/usr/bin/gather_audit_logs").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(strings.Contains(msg, "ERROR: To raise a Red Hat support request")).Should(o.BeTrue())
		o.Expect(strings.Contains(msg, "spec.audit.profile")).Should(o.BeTrue())

		compat_otp.By("4. Check if there is no new audit logs are generated after None profile setting.")
		user := "system:admin"
		errUser := oc.AsAdmin().WithoutNamespace().Run("login").Args("-u", user, "-n", "default").NotShowInfo().Execute()
		if errUser != nil {
			if exitErr, ok := errUser.(*exutil.ExitError); ok {
				e2e.Failf("oc login command failed for user %s. Stderr: %s", user, exitErr.StdErr)
			} else {
				e2e.Failf("oc login command failed for user %s with a non-ExitError: %v", user, errUser)
			}
		}
		// Define the command to run on each node
		now := time.Now().UTC().Format("2006-01-02 15:04:05")
		script := fmt.Sprintf(`for logpath in kube-apiserver oauth-apiserver openshift-apiserver; do grep -h system:authenticated:oauth /var/log/${logpath}/audit*.log | jq -c 'select (.requestReceivedTimestamp | .[0:19] + "Z" | fromdateiso8601 > "%s")' >> /tmp/OCP-43261-$logpath.json; done; cat /tmp/OCP-43261-*.json`, now)
		compat_otp.By("4.1 Get all master nodes.")
		masterNodes, getAllMasterNodesErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(getAllMasterNodesErr).NotTo(o.HaveOccurred())
		o.Expect(masterNodes).NotTo(o.BeEmpty())
		counter := 0
		for _, masterNode := range masterNodes {
			compat_otp.By(fmt.Sprintf("4.2 Get audit log file from %s", masterNode))
			masterNodeLogs, checkLogFileErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, masterNode, []string{"--quiet=true", "--to-namespace=openshift-kube-apiserver"}, "bash", "-c", script)
			o.Expect(checkLogFileErr).NotTo(o.HaveOccurred())
			errCount := strings.Count(strings.TrimSpace(masterNodeLogs), "\n")
			if errCount > 0 {
				e2e.Logf("Error logs on master node %v :: %v", masterNode, masterNodeLogs)
			}
			counter = errCount + counter
		}
		if counter > 0 {
			e2e.Failf("Audit logs counts increased :: %d", counter)
		}
	})

	// author: kewang@redhat.com
	// Disruptive/Slow: adds htpasswd test users and configures customRules profiles including "None",
	// then reverts.
	g.It("[OTP][OCP-73410] Support customRules list for by-group with none profile to the audit configuration [Disruptive][Slow]", ote.Informing(), func() {
		var (
			patchCustomRules string
			users            []User
			usersHTpassFile  string
			htPassSecret     string
		)

		defer func() {
			contextErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("use-context", "admin").Execute()
			o.Expect(contextErr).NotTo(o.HaveOccurred())
			contextOutput, contextErr := oc.AsAdmin().WithoutNamespace().Run("whoami").Args("--show-context").Output()
			o.Expect(contextErr).NotTo(o.HaveOccurred())
			e2e.Logf("Context after rollback :: %v", contextOutput)

			//Reset customRules profile to default one.
			output := setAuditProfile(oc, "apiserver/cluster", `[{"op": "remove", "path": "/spec/audit"}]`)
			if strings.Contains(output, "patched (no change)") {
				e2e.Logf("Apiserver/cluster's audit profile not changed from the default values")
			}
			userCleanup(oc, users, usersHTpassFile, htPassSecret)
		}()

		// Get user detail used by the test and cleanup after execution.
		users, usersHTpassFile, htPassSecret = getNewUser(oc, 4)

		compat_otp.By("1. Configure audit config for customRules system:authenticated:oauth profile as None and audit profile as Default")
		patchCustomRules = `[{"op": "replace", "path": "/spec/audit", "value": {"customRules": [ {"group": "system:authenticated:oauth","profile": "None"}],"profile": "Default"}}]`
		setAuditProfile(oc, "apiserver/cluster", patchCustomRules)

		compat_otp.By("2. Check audit events should be zero after login operation")
		verifyAuditEvents(oc, "system:authenticated:oauth", users[2].Username, users[2].Password, 120*time.Second, 20*time.Second, 0)

		compat_otp.By("3. Configure audit config for customRules system:authenticated:oauth profile as Default and audit profile as Default")
		patchCustomRules = `[{"op": "replace", "path": "/spec/audit", "value": {"customRules": [ {"group": "system:authenticated:oauth","profile": "Default"}],"profile": "Default"}}]`
		setAuditProfile(oc, "apiserver/cluster", patchCustomRules)

		compat_otp.By("4. Check audit events should be greater than zero after login operation")
		verifyAuditEvents(oc, "system:authenticated:oauth", users[3].Username, users[3].Password, 120*time.Second, 20*time.Second, 1)
	})

	// author: dpunia@redhat.com
	// Disruptive, SNO-only: forces kube-apiserver to fail rollout with a bad unsupportedConfigOverrides
	// value, then verifies it falls back to the last-known-good revision.
	g.It("[OTP][OCP-78850] SNO kube-apiserver can fall back to last good revision well when failing to roll out [Disruptive]", ote.Informing(), func() {
		if !isSNOCluster(oc) {
			g.Skip("This is not a SNO cluster, skip.")
		}

		nodes, nodeGetError := compat_otp.GetAllNodes(oc)
		o.Expect(nodeGetError).NotTo(o.HaveOccurred())

		e2e.Logf("Check openshift-kube-apiserver pods current revision before changes")
		out, revisionChkError := oc.WithoutNamespace().Run("get").Args("po", "-n", "openshift-kube-apiserver", "-l=apiserver", "-o", "jsonpath={.items[*].metadata.labels.revision}").Output()
		o.Expect(revisionChkError).NotTo(o.HaveOccurred())
		PreRevision, _ := strconv.Atoi(out)
		e2e.Logf("Current revision Count: %v", PreRevision)

		defer func() {
			compat_otp.By("Roll Out Step 1 Changes")
			patch := `[{"op": "replace", "path": "/spec/unsupportedConfigOverrides", "value": null}]`
			rollOutError := oc.AsAdmin().WithoutNamespace().Run("patch").Args("kubeapiserver/cluster", "--type=json", "-p", patch).Execute()
			o.Expect(rollOutError).NotTo(o.HaveOccurred())

			compat_otp.By("7) Check Kube-apiserver operator Roll Out with new revision count")
			rollOutError = wait.PollUntilContextTimeout(context.Background(), 100*time.Second, 900*time.Second, false, func(cxt context.Context) (bool, error) {
				Output, operatorChkError := oc.WithoutNamespace().Run("get").Args("co/kube-apiserver").Output()
				if operatorChkError == nil {
					matched, _ := regexp.MatchString("True.*False.*False", Output)
					if matched {
						out, revisionChkErr := oc.WithoutNamespace().Run("get").Args("po", "-n", "openshift-kube-apiserver", "-l=apiserver", "-o", "jsonpath={.items[*].metadata.labels.revision}").Output()
						PostRevision, _ := strconv.Atoi(out)
						o.Expect(revisionChkErr).NotTo(o.HaveOccurred())
						o.Expect(PostRevision).Should(o.BeNumerically(">", PreRevision), "Validation failed as PostRevision value not greater than PreRevision")
						e2e.Logf("Kube-apiserver operator Roll Out Successfully with new revision count")
						e2e.Logf("Step 7, Test Passed")
						return true, nil
					}
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(rollOutError, "Step 7, Test Failed: Kube-apiserver operator failed to Roll Out with new revision count")
		}()

		compat_otp.By("1) Add invalid configuration to kube-apiserver to make it failed")
		patch := `[{"op": "replace", "path": "/spec/unsupportedConfigOverrides", "value": {"apiServerArguments":{"foo":["bar"]}}}]`
		configError := oc.AsAdmin().WithoutNamespace().Run("patch").Args("kubeapiserver/cluster", "--type=json", "-p", patch).Execute()
		o.Expect(configError).NotTo(o.HaveOccurred())

		compat_otp.By("2) Check new startup-monitor pod created & running under openshift-kube-apiserver project")
		podChkError := wait.PollUntilContextTimeout(context.Background(), 3*time.Second, 180*time.Second, false, func(cxt context.Context) (bool, error) {
			out, runError := oc.WithoutNamespace().Run("get").Args("po", "-n", "openshift-kube-apiserver", "-l=app=installer", "-o", `jsonpath='{.items[?(@.status.phase=="Running")].status.phase}'`).Output()
			if runError == nil {
				if matched, _ := regexp.MatchString("Running", out); matched {
					e2e.Logf("Step 2, Test Passed: Startup-monitor pod created & running under openshift-kube-apiserver project")
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(podChkError, "Step 2, Test Failed: Failed to Create startup-monitor pod")

		compat_otp.By("3) Check kube-apiserver to fall back to previous good revision")
		fallbackError := wait.PollUntilContextTimeout(context.Background(), 100*time.Second, 900*time.Second, false, func(cxt context.Context) (bool, error) {
			annotations, fallbackErr := oc.WithoutNamespace().Run("get").Args("po", "-n", "openshift-kube-apiserver", "-l=apiserver", "-o", `jsonpath={.items[*].metadata.annotations.startup-monitor\.static-pods\.openshift\.io/fallback-for-revision}`).Output()
			if fallbackErr == nil {
				failedRevision, _ := strconv.Atoi(annotations)
				o.Expect(failedRevision - 1).Should(o.BeNumerically("==", PreRevision))
				compat_otp.By("Check created soft-link kube-apiserver-last-known-good to the last good revision")
				out, fileChkError := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, nodes[0], []string{"--to-namespace=openshift-kube-apiserver"}, "bash", "-c", "ls -l /etc/kubernetes/static-pod-resources/kube-apiserver-last-known-good")
				o.Expect(fileChkError).NotTo(o.HaveOccurred())
				o.Expect(out).To(o.ContainSubstring("kube-apiserver-pod.yaml"))
				e2e.Logf("Step 3, Test Passed: Cluster is fall back to last good revision")
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(fallbackError, "Step 3, Test Failed: Failed to start kube-apiserver with previous good revision")

		compat_otp.By("4: Check startup-monitor pod was created during fallback and currently in Stopped/Removed state")
		cmd := "journalctl -u crio --since '10min ago'| grep 'startup-monitor' | grep -E 'Stopped container|Removed container'"
		out, journalctlErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, nodes[0], []string{"--to-namespace=openshift-kube-apiserver"}, "bash", "-c", cmd)
		o.Expect(journalctlErr).NotTo(o.HaveOccurred())
		o.Expect(out).ShouldNot(o.BeEmpty())
		e2e.Logf("Step 4, Test Passed : Startup-monitor pod was created and Stopped/Removed state")

		compat_otp.By("5) Check kube-apiserver operator status changed to degraded")
		expectedStatus := map[string]string{"Degraded": "True"}
		operatorChkErr := waitCoBecomes(oc, "kube-apiserver", 900, expectedStatus)
		compat_otp.AssertWaitPollNoErr(operatorChkErr, "Step 5, Test Failed: kube-apiserver operator failed to Degraded")

		compat_otp.By("6) Check kubeapiserver operator nodeStatuses show lastFallbackCount info correctly")
		out, revisionChkErr := oc.WithoutNamespace().Run("get").Args("kubeapiserver/cluster", "-o", "jsonpath='{.status.nodeStatuses[*].lastFailedRevisionErrors}'").Output()
		o.Expect(revisionChkErr).NotTo(o.HaveOccurred())
		o.Expect(out).To(o.ContainSubstring(fmt.Sprintf("fallback to last-known-good revision %v took place", PreRevision)))
		e2e.Logf("Step 6, Test Passed")
	})

	// author: rgangwar@redhat.com
	// Longduration: loops 15x creating/deleting a namespace+app, asserting the create-to-ready-to-delete
	// window stays under 90s to catch raft/cache delay regressions in namespace admission.
	g.It("[OTP][OCP-10350] compensate for raft/cache delay in namespace admission", ote.Informing(), func() {
		tmpnamespace := "ocp-10350" + compat_otp.GetRandomString()
		defer oc.AsAdmin().Run("delete").Args("ns", tmpnamespace, "--ignore-not-found").Execute()
		compat_otp.By("1.) Create new namespace")
		// Description of case: we observe how long it takes to delete one Terminating namespace that has a
		// Terminating pod when the cluster is under some load. Wait up to 200 seconds and also calculate the
		// actual time so that when it FIRST hits > 200 seconds, we fail it IMMEDIATELY. This way we know the
		// actual time DIRECTLY from the test logs, useful to file a performance bug with PRESENT evidence.
		expectedOutageTime := 90
		for i := 0; i < 15; i++ {
			var namespaceErr error
			projectSuccTime := time.Now()
			err := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
				namespaceOutput, namespaceErr := oc.WithoutNamespace().Run("create").Args("ns", tmpnamespace).Output()
				if namespaceErr == nil {
					e2e.Logf("oc create ns %v created successfully", tmpnamespace)
					projectSuccTime = time.Now()
					o.Expect(namespaceOutput).Should(o.ContainSubstring(fmt.Sprintf("namespace/%v created", tmpnamespace)), fmt.Sprintf("namespace/%v not created", tmpnamespace))
					return true, nil
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(err, fmt.Sprintf("oc create ns %v failed :: %v", tmpnamespace, namespaceErr))

			compat_otp.By("2.) Create new app")
			var apperr error
			errApp := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
				apperr := oc.WithoutNamespace().Run("new-app").Args("quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83", "-n", tmpnamespace, "--import-mode=PreserveOriginal").Execute()
				if apperr != nil {
					return false, nil
				}
				e2e.Logf("oc new app succeeded")
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(errApp, fmt.Sprintf("oc new app failed :: %v", apperr))

			var poderr error
			errPod := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
				podOutput, poderr := oc.WithoutNamespace().Run("get").Args("pod", "-n", tmpnamespace, "--no-headers").Output()
				if poderr == nil && strings.Contains(podOutput, "Running") {
					e2e.Logf("Pod %v succesfully", podOutput)
					return true, nil
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(errPod, fmt.Sprintf("Pod not running :: %v", poderr))

			compat_otp.By("3.) Delete new namespace")
			var delerr error
			projectdelerr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
				delerr = oc.Run("delete").Args("namespace", tmpnamespace).Execute()
				if delerr != nil {
					return false, nil
				}
				e2e.Logf("oc delete namespace succeeded")
				return true, nil
			})
			compat_otp.AssertWaitPollNoErr(projectdelerr, fmt.Sprintf("oc delete namespace failed :: %v", delerr))

			var chkNamespaceErr error
			errDel := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
				chkNamespaceOutput, chkNamespaceErr := oc.WithoutNamespace().Run("get").Args("namespace", tmpnamespace, "--ignore-not-found").Output()
				if chkNamespaceErr == nil && strings.Contains(chkNamespaceOutput, "") {
					e2e.Logf("Namespace deleted %v successfully", tmpnamespace)
					return true, nil
				}
				return false, nil
			})
			compat_otp.AssertWaitPollNoErr(errDel, fmt.Sprintf("Namespace %v not deleted successfully, still visible after delete :: %v", tmpnamespace, chkNamespaceErr))

			projectDelTime := time.Now()
			diff := projectDelTime.Sub(projectSuccTime)
			e2e.Logf("#### Namespace success and delete time(s) :: %f ####\n", diff.Seconds())
			if int(diff.Seconds()) > expectedOutageTime {
				e2e.Failf("#### Test case Failed in %d run :: The Namespace success and deletion outage time lasted %d longer than we expected %d", i, int(diff.Seconds()), expectedOutageTime)
			}
			e2e.Logf("#### Test case passed in %d run :: Namespace success and delete time(s) :: %f ####\n", i, diff.Seconds())
		}
	})

	// author: dpunia@redhat.com
	// Disruptive/Slow: adds htpasswd test users and configures customRules audit profiles, then reverts.
	g.It("[OTP][OCP-43336] Support customRules list for by-group profiles to the audit configuration [Disruptive][Slow]", ote.Informing(), func() {
		var (
			patchCustomRules string
			users            []User
			usersHTpassFile  string
			htPassSecret     string
		)

		defer func() {
			contextErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("use-context", "admin").Execute()
			o.Expect(contextErr).NotTo(o.HaveOccurred())
			contextOutput, contextErr := oc.AsAdmin().WithoutNamespace().Run("whoami").Args("--show-context").Output()
			o.Expect(contextErr).NotTo(o.HaveOccurred())
			e2e.Logf("Context after rollback :: %v", contextOutput)

			//Reset customRules profile to default one.
			output := setAuditProfile(oc, "apiserver/cluster", `[{"op": "remove", "path": "/spec/audit"}]`)
			if strings.Contains(output, "patched (no change)") {
				e2e.Logf("Apiserver/cluster's audit profile not changed from the default values")
			}
			userCleanup(oc, users, usersHTpassFile, htPassSecret)
		}()

		// Get user detail used by the test and cleanup after execution.
		users, usersHTpassFile, htPassSecret = getNewUser(oc, 2)

		compat_otp.By("1. Configure audit config for customRules system:authenticated:oauth profile as Default and audit profile as None")
		patchCustomRules = `[{"op": "replace", "path": "/spec/audit", "value": {"customRules": [ {"group": "system:authenticated:oauth","profile": "Default"}],"profile": "None"}}]`
		setAuditProfile(oc, "apiserver/cluster", patchCustomRules)

		compat_otp.By("2. Check audit events should be greater than zero after login operation")
		verifyAuditEvents(oc, "system:authenticated:oauth", users[0].Username, users[0].Password, 120*time.Second, 20*time.Second, 1)

		compat_otp.By("3. Configure audit config for customRules system:authenticated:oauth profile as Default & system:serviceaccounts:openshift-console-operator as WriteRequestBodies and audit profile as None")
		patchCustomRules = `[{"op": "replace", "path": "/spec/audit", "value": {"customRules": [ {"group": "system:authenticated:oauth","profile": "Default"}, {"group": "system:serviceaccounts:openshift-console-operator","profile": "WriteRequestBodies"}],"profile": "None"}}]`
		setAuditProfile(oc, "apiserver/cluster", patchCustomRules)

		compat_otp.By("4. Check audit events should be greater than zero after login operation")
		verifyAuditEvents(oc, "system:authenticated:oauth", users[1].Username, users[1].Password, 120*time.Second, 20*time.Second, 1)
		verifyAuditEvents(oc, "system:serviceaccounts:openshift-console-operator", users[1].Username, users[1].Password, 120*time.Second, 20*time.Second, 1)
	})

	// author: rgangwar@redhat.com
	// Disruptive/Slow: saturates CPU on a kube-apiserver pod's master node to verify the
	// ExtremelyHighIndividualControlPlaneCPU alert (or HighOverallControlPlaneCPU on SNO) fires.
	g.It("[OTP][OCP-47633] Update existing alert ExtremelyHighIndividualControlPlaneCPU [Slow][Disruptive]", ote.Informing(), func() {
		var (
			alert             = "ExtremelyHighIndividualControlPlaneCPU"
			alertSno          = "HighOverallControlPlaneCPU"
			alertBudget       = "KubeAPIErrorBudgetBurn"
			runbookURL        = "https://github.com/openshift/runbooks/blob/master/alerts/cluster-kube-apiserver-operator/ExtremelyHighIndividualControlPlaneCPU.md"
			runbookBudgetURL  = "https://github.com/openshift/runbooks/blob/master/alerts/cluster-kube-apiserver-operator/KubeAPIErrorBudgetBurn.md"
			alertTimeWarning  = "5m"
			alertTimeCritical = "1h"
			severity          = []string{"warning", "critical"}
			chkStr            string
			alertName         string
		)
		compat_otp.By("1. Check with cluster installed OCP 4.10 and later release, the following changes for existing alert " + alert + " have been applied.")
		output, alertSevErr := oc.Run("get").Args("prometheusrule/cpu-utilization", "-n", "openshift-kube-apiserver", "-o", `jsonpath='{.spec.groups[?(@.name=="control-plane-cpu-utilization")].rules[?(@.alert=="`+alert+`")].labels.severity}'`).Output()
		o.Expect(alertSevErr).NotTo(o.HaveOccurred())
		compat_otp.By("1) Check if cluster is SNO.")
		if !isSNOCluster(oc) {
			chkStr = fmt.Sprintf("%s %s", severity[0], severity[1])
			o.Expect(output).Should(o.ContainSubstring(chkStr), fmt.Sprintf("Not have new alert %s with severity :: %s : %s", alert, severity[0], severity[1]))
			e2e.Logf("Have new alert %s with severity :: %s : %s", alert, severity[0], severity[1])
		} else {
			o.Expect(output).Should(o.ContainSubstring(severity[1]), fmt.Sprintf("Not have new alert %s with severity :: %s", alert, severity[1]))
			e2e.Logf("Have new alert %s with severity :: %s", alert, severity[1])
		}

		e2e.Logf("Check reduce severity to %s and %s for :: %s : %s", severity[0], severity[1], alertTimeWarning, alertTimeCritical)
		output, alertTimeErr := oc.Run("get").Args("prometheusrule/cpu-utilization", "-n", "openshift-kube-apiserver", "-o", `jsonpath='{.spec.groups[?(@.name=="control-plane-cpu-utilization")].rules[?(@.alert=="`+alert+`")].for}'`).Output()
		o.Expect(alertTimeErr).NotTo(o.HaveOccurred())
		if !isSNOCluster(oc) {
			chkStr = fmt.Sprintf("%s %s", alertTimeWarning, alertTimeCritical)
			o.Expect(output).Should(o.ContainSubstring(chkStr), fmt.Sprintf("Not Have reduce severity to %s and %s for :: %s : %s", severity[0], severity[1], alertTimeWarning, alertTimeCritical))
			e2e.Logf("Have reduce severity to %s and %s for :: %s : %s", severity[0], severity[1], alertTimeWarning, alertTimeCritical)
		} else {
			o.Expect(output).Should(o.ContainSubstring(alertTimeCritical), fmt.Sprintf("Not Have reduce severity to %s for :: %s", severity[1], alertTimeCritical))
			e2e.Logf("Have reduce severity to %s for :: %s", severity[1], alertTimeCritical)
		}

		e2e.Logf("Check a run book url for %s", alert)
		output, alertRunbookErr := oc.Run("get").Args("prometheusrule/cpu-utilization", "-n", "openshift-kube-apiserver", "-o", `jsonpath='{.spec.groups[?(@.name=="control-plane-cpu-utilization")].rules[?(@.alert=="`+alert+`")].annotations.runbook_url}'`).Output()
		o.Expect(alertRunbookErr).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring(runbookURL), fmt.Sprintf("%s Runbook url not found :: %s", alert, runbookURL))
		e2e.Logf("Have a run book url for %s :: %s", alert, runbookURL)

		compat_otp.By("2. Provide run book url for " + alertBudget)
		output, alertKubeBudgetErr := oc.Run("get").Args("PrometheusRule", "-n", "openshift-kube-apiserver", "kube-apiserver-slos-basic", "-o", `jsonpath='{.spec.groups[?(@.name=="kube-apiserver-slos-basic")].rules[?(@.alert=="`+alertBudget+`")].annotations.runbook_url}`).Output()
		o.Expect(alertKubeBudgetErr).NotTo(o.HaveOccurred())
		o.Expect(output).Should(o.ContainSubstring(runbookBudgetURL), fmt.Sprintf("%s runbookUrl not found :: %s", alertBudget, runbookBudgetURL))
		e2e.Logf("Run book url for %s :: %s", alertBudget, runbookBudgetURL)

		compat_otp.By("3. Test the ExtremelyHighIndividualControlPlaneCPU alerts firing")
		e2e.Logf("Check how many cpus are there in the master node")
		masterNode, masterErr := compat_otp.GetFirstMasterNode(oc)
		o.Expect(masterErr).NotTo(o.HaveOccurred())
		e2e.Logf("Master node is %v : ", masterNode)
		cmd := `lscpu | grep '^CPU(s):'`
		cpuCores, cpuErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, masterNode, []string{"--quiet=true", "--to-namespace=openshift-kube-apiserver"}, "bash", "-c", cmd)
		o.Expect(cpuErr).NotTo(o.HaveOccurred())
		regexStr := regexp.MustCompile(`CPU\S+\s+\S+`)
		cpuCore := strings.Split(regexStr.FindString(cpuCores), ":")
		noofCPUCore := strings.TrimSpace(cpuCore[1])
		e2e.Logf("Number of cpu :: %v", noofCPUCore)

		e2e.Logf("Run script to add cpu workload to one kube-apiserver pod on the master.")
		labelString := "apiserver"
		masterPods, err := compat_otp.GetAllPodsWithLabel(oc, "openshift-kube-apiserver", labelString)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(masterPods).ShouldNot(o.BeEmpty(), "Not able to get pod")
		defer func() {
			err = oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-kube-apiserver", masterPods[0], "--", "/bin/sh", "-c", `ps -ef | grep md5sum | grep -v grep | awk '{print $2}' | xargs kill -HUP`).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}()
		_, _, _, execPodErr := oc.AsAdmin().WithoutNamespace().Run("exec").Args("-n", "openshift-kube-apiserver", masterPods[0], "--", "/bin/sh", "-c", `seq `+noofCPUCore+` | xargs -P0 -n1 md5sum /dev/zero`).Background()
		o.Expect(execPodErr).NotTo(o.HaveOccurred())

		e2e.Logf("Check alert ExtremelyHighIndividualControlPlaneCPU firing")
		errWatcher := wait.PollUntilContextTimeout(context.Background(), 60*time.Second, 900*time.Second, false, func(cxt context.Context) (bool, error) {
			alertOutput, alertErr := GetAlertsByName(oc, "ExtremelyHighIndividualControlPlaneCPU")
			o.Expect(alertErr).NotTo(o.HaveOccurred())
			alertNameData := gjson.Parse(alertOutput).String()
			if isSNOCluster(oc) {
				alertName = alertSno
			} else {
				alertName = alert
			}
			alertOutputWarning1 := gjson.Get(alertNameData, `data.alerts.#(labels.alertname=="`+alertName+`")#`).String()
			alertOutputWarning2 := gjson.Get(alertOutputWarning1, `#(labels.severity=="`+severity[0]+`").state`).String()

			if strings.Contains(string(alertOutputWarning2), "firing") {
				e2e.Logf("%s with %s is firing", alertName, severity[0])
				alertOutputWarning1 = gjson.Get(alertNameData, `data.alerts.#(labels.alertname=="`+alert+`")#`).String()
				alertOuptutCritical := gjson.Get(alertOutputWarning1, `#(labels.severity=="`+severity[1]+`").state`).String()
				o.Expect(alertOuptutCritical).Should(o.ContainSubstring("pending"), fmt.Sprintf("%s with %s is not pending", alert, severity[1]))
				e2e.Logf("%s with %s is pending", alert, severity[1])
				return true, nil
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(errWatcher, fmt.Sprintf("%s with %s is not firing", alert, severity[0]))
	})

	// author: kewang@redhat.com
	// Slow: waits up to 25 minutes for the service-serving-cert to regenerate once close to expiry.
	g.It("[OTP][OCP-10873] Access app through secure service and regenerate service serving certs if it about to expire [ConnectedOnly][Slow]", ote.Informing(), func() {
		var (
			filename     = "aosqe-pod-for-ping.json"
			podName      = "hello-pod"
			caseID       = "ocp10873"
			stepExecTime time.Time
		)

		compat_otp.By("1) Create new project for the test case.")
		oc.SetupProject()
		testNamespace := oc.Namespace()

		compat_otp.By("2) The appropriate pod security labels are applied to the new project.")
		applyLabel(oc, asAdmin, withoutNamespace, "ns", testNamespace, "security.openshift.io/scc.podSecurityLabelSync=false", "--overwrite")
		applyLabel(oc, asAdmin, withoutNamespace, "ns", testNamespace, "pod-security.kubernetes.io/warn=privileged", "--overwrite")
		applyLabel(oc, asAdmin, withoutNamespace, "ns", testNamespace, "pod-security.kubernetes.io/audit=privileged", "--overwrite")
		applyLabel(oc, asAdmin, withoutNamespace, "ns", testNamespace, "pod-security.kubernetes.io/enforce=privileged", "--overwrite")

		compat_otp.By("3) Add SCC privileged to the project.")
		err := oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-scc-to-group", "privileged", "system:serviceaccounts:"+testNamespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("4) Create a service.")
		template := getTestDataFilePath(caseID + "-svc.json")
		svcErr := oc.Run("create").Args("-f", template).Execute()
		o.Expect(svcErr).NotTo(o.HaveOccurred())

		stepExecTime = time.Now()

		compat_otp.By("5) Create a nginx webserver app with deployment.")
		template = getTestDataFilePath(caseID + "-dc.yaml")
		dcErr := oc.Run("create").Args("-f", template).Execute()
		o.Expect(dcErr).NotTo(o.HaveOccurred())

		appPodName := getPodsListByLabel(oc.AsAdmin(), testNamespace, "name=web-server-rc")[0]
		compat_otp.AssertPodToBeReady(oc, appPodName, testNamespace)
		cmName, err := getResource(oc, asAdmin, withoutNamespace, "configmaps", "nginx-config", "-n", testNamespace, "-o=jsonpath={.metadata.name}")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(cmName).ShouldNot(o.BeEmpty(), "The ConfigMap 'nginx-config' name should not be empty")

		compat_otp.By(fmt.Sprintf("6.1) Create pod with resource file %s.", filename))
		template = getTestDataFilePath(filename)
		err = oc.Run("create").Args("-f", template).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By(fmt.Sprintf("6.2) Wait for pod with name %s to be ready.", podName))
		compat_otp.AssertPodToBeReady(oc, podName, testNamespace)

		url := fmt.Sprintf("https://hello.%s.svc:443", testNamespace)
		execCmd := fmt.Sprintf("curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt %s", url)
		curlCmdOutput := ExecCommandOnPod(oc, podName, testNamespace, execCmd)
		o.Expect(curlCmdOutput).Should(o.ContainSubstring("Hello-OpenShift"))

		compat_otp.By("7) Extract the cert and key from secret ssl-key.")
		err = oc.AsAdmin().WithoutNamespace().Run("extract").Args("-n", testNamespace, "secret/ssl-key", "--to", tmpdir).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		tlsCrtFile := filepath.Join(tmpdir, "tls.crt")
		tlsCrt, err := os.ReadFile(tlsCrtFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(tlsCrt).ShouldNot(o.BeEmpty())

		// Set the new expiry(1 hour + 1 minute) after the time of the secret ssl-key was created
		compat_otp.By("8) Set the new expiry annotations to the secret ssl-key.")
		tlsCrtCreation, err := getResource(oc, asAdmin, withoutNamespace, "secret", "ssl-key", "-n", testNamespace, "-o=jsonpath={.metadata.creationTimestamp}")
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(tlsCrtCreation).ShouldNot(o.BeEmpty())
		e2e.Logf("created time:%s", tlsCrtCreation)
		tlsCrtCreationTime, err := time.Parse(time.RFC3339, tlsCrtCreation)
		o.Expect(err).NotTo(o.HaveOccurred())
		newExpiry := tlsCrtCreationTime.Add(time.Since(stepExecTime) + 1*time.Hour + 60*time.Second)
		newExpiryStr := fmt.Sprintf(`"%s"`, newExpiry.Format(time.RFC3339))
		logger.Debugf("The new expiry of the secret ssl-key is %s", newExpiryStr)

		annotationPatch := fmt.Sprintf(`{"metadata":{"annotations": {"service.alpha.openshift.io/expiry": %s, "service.beta.openshift.io/expiry": %s}}}`, newExpiryStr, newExpiryStr)
		errPatch := oc.AsAdmin().WithoutNamespace().Run("patch").Args("secret", "ssl-key", "-n", testNamespace, "--type=merge", "-p", annotationPatch).Execute()
		o.Expect(errPatch).NotTo(o.HaveOccurred())

		compat_otp.By("9) Check secret ssl-key again and shouldn't change When the expiry time is greater than 1h.")
		o.Eventually(func() bool {
			err = oc.AsAdmin().WithoutNamespace().Run("extract").Args("-n", testNamespace, "secret/ssl-key", "--to", tmpdir, "--confirm=true").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
			tlsCrt1, err := os.ReadFile(tlsCrtFile)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(tlsCrt1).ShouldNot(o.BeEmpty())
			if !bytes.Equal(tlsCrt, tlsCrt1) {
				logger.Infof("When the expiry time has less than 1h left, the cert has been regenerated")
				return true
			}
			logger.Infof("When the expiry time has more than 1h left, the cert will not regenerate")
			return false
		}, "25m", "60s").Should(o.Equal(true),
			"Failed to regenerate the new secret ssl-key When the expiry time is greater than 1h")

		compat_otp.By(fmt.Sprintf("10) Using the regenerated secret ssl-key to access web app in pod %s without error.", podName))
		compat_otp.AssertPodToBeReady(oc, podName, testNamespace)
		curlCmdOutput = ExecCommandOnPod(oc, podName, testNamespace, execCmd)
		o.Expect(curlCmdOutput).Should(o.ContainSubstring("Hello-OpenShift"))
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-12036] User can pull a private image from a registry when a pull secret is defined [ConnectedOnly][Serial]", ote.Informing(), func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		architecture.SkipArchitectures(oc, architecture.MULTI)
		compat_otp.By("1) Create a new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By("2) Build hello-world from external source")
		helloWorldSource := "quay.io/openshifttest/ruby-27:1.2.0~https://github.com/openshift/ruby-hello-world"
		buildName := fmt.Sprintf("ocp12036-test-%s", strings.ToLower(compat_otp.RandStr(5)))
		err := oc.Run("new-build").Args(helloWorldSource, "--name="+buildName, "-n", namespace, "--import-mode=PreserveOriginal").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) Wait for hello-world build to success")
		buildClient := oc.BuildClient().BuildV1().Builds(oc.Namespace())
		err = compat_otp.WaitForABuild(buildClient, buildName+"-1", nil, nil, nil)
		if err != nil {
			compat_otp.DumpBuildLogs(buildName, oc)
		}
		compat_otp.AssertWaitPollNoErr(err, "build is not complete")

		compat_otp.By("4) Get dockerImageRepository value from imagestreams test")
		dockerImageRepository1, err := oc.Run("get").Args("imagestreams", buildName, "-o=jsonpath={.status.dockerImageRepository}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		dockerServer := strings.Split(strings.TrimSpace(dockerImageRepository1), "/")
		o.Expect(dockerServer).NotTo(o.BeEmpty())

		compat_otp.By("5) Create another project with the second user")
		oc.SetupProject()

		compat_otp.By("6) Get access token")
		token, err := oc.Run("whoami").Args("-t").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("7) Give user admin permission")
		username := oc.Username()
		err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", username).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("8) Create secret for private image under project")
		err = oc.WithoutNamespace().AsAdmin().Run("create").Args("secret", "docker-registry", "user1-dockercfg", "--docker-email=any@any.com", "--docker-server="+dockerServer[0], "--docker-username="+username, "--docker-password="+token, "-n", oc.Namespace()).NotShowInfo().Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("9) Create new deploymentconfig from the dockerImageRepository fetched in step 4")
		deploymentConfigYaml, err := oc.Run("create").Args("deploymentconfig", "frontend", "--image="+dockerImageRepository1, "--dry-run=client", "-o=yaml").OutputToFile("ocp12036-dc.yaml")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("10) Modify the deploymentconfig and create a new deployment.")
		compat_otp.ModifyYamlFileContent(deploymentConfigYaml, []compat_otp.YamlReplace{
			{
				Path:  "spec.template.spec.containers.0.imagePullPolicy",
				Value: "Always",
			},
			{
				Path:  "spec.template.spec.imagePullSecrets",
				Value: "- name: user1-dockercfg",
			},
		})
		err = oc.Run("create").Args("-f", deploymentConfigYaml).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("11) Check if pod is properly running with expected status.")
		podsList := getPodsListByLabel(oc.AsAdmin(), oc.Namespace(), "deploymentconfig=frontend")
		compat_otp.AssertPodToBeReady(oc, podsList[0], oc.Namespace())
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-11905] Use well-formed pull secret with incorrect credentials will fail to build and deploy [ConnectedOnly][Serial]", ote.Informing(), func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		architecture.SkipArchitectures(oc, architecture.MULTI)
		compat_otp.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		compat_otp.By("1) Create a new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		compat_otp.By("2) Build hello-world from external source")
		helloWorldSource := "quay.io/openshifttest/ruby-27:1.2.0~https://github.com/openshift/ruby-hello-world"
		buildName := fmt.Sprintf("ocp11905-test-%s", strings.ToLower(compat_otp.RandStr(5)))
		err := oc.Run("new-build").Args(helloWorldSource, "--name="+buildName, "-n", namespace, "--import-mode=PreserveOriginal").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("3) Wait for hello-world build to success")
		buildClient := oc.BuildClient().BuildV1().Builds(oc.Namespace())
		err = compat_otp.WaitForABuild(buildClient, buildName+"-1", nil, nil, nil)
		if err != nil {
			compat_otp.DumpBuildLogs(buildName, oc)
		}
		compat_otp.AssertWaitPollNoErr(err, "build is not complete")

		compat_otp.By("4) Get dockerImageRepository value from imagestreams test")
		dockerImageRepository1, err := oc.Run("get").Args("imagestreams", buildName, "-o=jsonpath={.status.dockerImageRepository}").Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		dockerServer := strings.Split(strings.TrimSpace(dockerImageRepository1), "/")
		o.Expect(dockerServer).NotTo(o.BeEmpty())

		compat_otp.By("5) Create another project with the second user")
		oc.SetupProject()

		compat_otp.By("6) Give user admin permission")
		username := oc.Username()
		err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("policy", "add-cluster-role-to-user", "cluster-admin", username).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("7) Create secret for private image under project with wrong password")
		err = oc.WithoutNamespace().AsAdmin().Run("create").Args("secret", "docker-registry", "user1-dockercfg", "--docker-email=any@any.com", "--docker-server="+dockerServer[0], "--docker-username="+username, "--docker-password=password", "-n", oc.Namespace()).NotShowInfo().Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("8) Create new deploymentconfig from the dockerImageRepository fetched in step 4")
		deploymentConfigYaml, err := oc.Run("create").Args("deploymentconfig", "frontend", "--image="+dockerImageRepository1, "--dry-run=client", "-o=yaml").OutputToFile("ocp11905-dc.yaml")
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("9) Modify the deploymentconfig and create a new deployment.")
		compat_otp.ModifyYamlFileContent(deploymentConfigYaml, []compat_otp.YamlReplace{
			{
				Path:  "spec.template.spec.containers.0.imagePullPolicy",
				Value: "Always",
			},
			{
				Path:  "spec.template.spec.imagePullSecrets",
				Value: "- name: user1-dockercfg",
			},
		})
		err = oc.Run("create").Args("-f", deploymentConfigYaml).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		compat_otp.By("10) Check if pod is running with the expected status.")
		err = wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			podOutput, err := oc.Run("get").Args("pod").Output()
			if err == nil {
				matched, _ := regexp.MatchString("frontend-1-.*(ImagePullBackOff|ErrImagePull)", podOutput)
				if matched {
					e2e.Logf("Pod is running with expected status\n%s", podOutput)
					return true, nil
				}
			}
			return false, nil
		})
		compat_otp.AssertWaitPollNoErr(err, "pod did not show up with the expected status")
	})

	// author: rgangwar@redhat.com
	g.It("[OTP][OCP-68629] Audit log files of apiservers should not have too permissive mode", ote.Informing(), func() {
		directories := []string{
			"/var/log/kube-apiserver/",
			"/var/log/openshift-apiserver/",
			"/var/log/oauth-apiserver/",
		}

		compat_otp.By("Get all master nodes.")
		masterNodes, getAllMasterNodesErr := compat_otp.GetClusterNodesBy(oc, "master")
		o.Expect(getAllMasterNodesErr).NotTo(o.HaveOccurred())
		o.Expect(masterNodes).NotTo(o.BeEmpty())

		for i, directory := range directories {
			compat_otp.By(fmt.Sprintf("%v) Checking permissions for directory: %s\n", i+1, directory))
			// Skip checking of hidden files
			cmd := fmt.Sprintf(`find %s -type f ! -perm 600 ! -name ".*" -exec ls -l {} +`, directory)
			for _, masterNode := range masterNodes {
				e2e.Logf("Checking permissions for directory: %s on node %s", directory, masterNode)
				masterNodeOutput, checkFileErr := compat_otp.DebugNodeRetryWithOptionsAndChroot(oc, masterNode, []string{"--quiet=true", "--to-namespace=openshift-kube-apiserver"}, "bash", "-c", cmd)
				o.Expect(checkFileErr).NotTo(o.HaveOccurred())

				// Filter out the specific warning from the output
				lines := strings.Split(string(masterNodeOutput), "\n")
				cleanedLines := make([]string, 0, len(lines))

				for _, line := range lines {
					if !strings.Contains(line, "Warning: metadata.name: this is used in the Pod's hostname") {
						cleanedLine := strings.TrimSpace(line)
						if cleanedLine != "" {
							cleanedLines = append(cleanedLines, cleanedLine)
						}
					}
				}

				// Iterate through the cleaned lines to check file permissions
				for _, line := range cleanedLines {
					if strings.Contains(line, "-rw-------.") {
						e2e.Logf("Node %s has a file with valid permissions 600 in %s:\n %s\n", masterNode, directory, line)
					} else {
						e2e.Failf("Node %s has a file with invalid permissions in %s:\n %v", masterNode, directory, line)
					}
				}
			}
		}
	})

	// author: kewang@redhat.com
	g.It("[OTP][OCP-84783] Verify certificates for authentication and encryption of communications between components and clients", ote.Informing(), func() {
		compat_otp.By("1) run TLS secret checks.")

		ns := "openshift-kube-apiserver"
		e2e.Logf("====================================")
		e2e.Logf(" OpenShift TLS Secrets Verification")
		e2e.Logf("====================================")

		secretsJSON, err := oc.AsAdmin().WithoutNamespace().
			Run("get").Args("secret", "-n", ns, "-ojson").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		var secretList struct {
			Items []struct {
				Type     string            `json:"type"`
				Data     map[string]string `json:"data"`
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
			} `json:"items"`
		}

		if err := json.Unmarshal([]byte(secretsJSON), &secretList); err != nil {
			e2e.Failf("failed to parse oc secret json: %v", err)
		}

		for _, s := range secretList.Items {
			if s.Type != "kubernetes.io/tls" {
				continue
			}
			name := s.Metadata.Name
			o.Expect(name).ShouldNot(o.BeEmpty(), "failed to get the secret name from metadata of service %s", s.Metadata.Name)
			rawcrt, ok := s.Data["tls.crt"]
			if !ok || rawcrt == "" {
				e2e.Logf("%s/%s\n    No tls.crt found\n\n", ns, name)
				continue
			}

			decoded, err := base64.StdEncoding.DecodeString(rawcrt)
			if err != nil {
				decoded, err = base64.RawStdEncoding.DecodeString(rawcrt)
				if err != nil {
					e2e.Logf("%s/%s\n    failed to base64-decode tls.crt: %v\n\n", ns, name, err)
					continue
				}
			}

			e2e.Logf("%s/%s\n", ns, name)
			parseAndCheckPEMs(decoded, fmt.Sprintf("%s/%s", ns, name))
		}

		compat_otp.By("2) run configmap checks.")
		e2e.Logf("====================================")
		e2e.Logf(" OpenShift CA Bundles Verification")
		e2e.Logf("====================================")

		ns = "openshift-config-managed"

		// user-specified list
		cms := []struct {
			name string
			key  string
		}{
			{"kube-apiserver-server-ca", "ca-bundle.crt"},
			{"kube-apiserver-client-ca", "ca-bundle.crt"},
			{"kube-root-ca.crt", "ca.crt"},
			{"trusted-ca-bundle", "ca-bundle.crt"},
			{"service-ca", "ca-bundle.crt"},
		}

		for _, cm := range cms {
			cmJSON, err := oc.AsAdmin().WithoutNamespace().
				Run("get").Args("cm", cm.name, "-n", ns, "-ojson").Output()
			if err != nil {
				e2e.Logf("%s/%s (%s)\n    failed to get configmap: %v\n\n", ns, cm.name, cm.key, err)
				continue
			}

			var cmObj struct {
				Data map[string]string `json:"data"`
			}
			if err := json.Unmarshal([]byte(cmJSON), &cmObj); err != nil {
				e2e.Logf("%s/%s (%s)\n    failed to parse configmap json: %v\n\n", ns, cm.name, cm.key, err)
				continue
			}

			val, ok := cmObj.Data[cm.key]
			if !ok || val == "" {
				// fallback: search any key containing "ca" or "crt"
				found := false
				for k, v := range cmObj.Data {
					kl := strings.ToLower(k)
					if strings.Contains(kl, "ca") || strings.Contains(kl, "crt") {
						if v != "" {
							e2e.Logf("%s/%s (using key %s)\n", ns, cm.name, k)
							parseAndCheckPEMs([]byte(v), fmt.Sprintf("%s/%s(%s)", ns, cm.name, k))
							found = true
							break
						}
					}
				}
				if !found {
					e2e.Logf("%s/%s (%s)\n    key not found in configmap\n\n", ns, cm.name, cm.key)
				}
				continue
			}

			// data is the PEM bundle
			e2e.Logf("%s/%s (%s)\n", ns, cm.name, cm.key)
			parseAndCheckPEMs([]byte(val), fmt.Sprintf("%s/%s(%s)", ns, cm.name, cm.key))
		}

		e2e.Logf("Verification complete.")
	})
})
