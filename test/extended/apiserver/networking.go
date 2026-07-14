package apiserver

import (
	"context"
	"fmt"
	"math/rand"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-api-machinery][Feature:APIServer] API_Server Networking", func() {
	defer g.GinkgoRecover()

	oc := exutil.NewCLI("apiserver-networking")

	g.It("Author:zxiao-HyperShiftMGMT-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-11364-[platformmanagement_public_624] Create nodeport service", func() {
		var (
			generatedNodePort int
			curlOutput        string
			url               string
			curlErr           error
			filename          = "hello-pod.json"
			podName           = "hello-openshift"
		)

		g.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		g.By(fmt.Sprintf("2) Create pod with resource file %s", filename))
		template := getTestDataFilePath(filename)
		err := oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("3) Wait for pod with name %s to be ready", podName))
		assertPodToBeReady(oc, podName, namespace)

		g.By(fmt.Sprintf("4) Check host ip for pod %s", podName))
		hostIP, err := oc.Run("get").Args("pods", podName, "-o=jsonpath={.status.hostIP}", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(hostIP).NotTo(o.Equal(""))
		e2e.Logf("Get host ip %s", hostIP)

		g.By("5) Create nodeport service with random service port")
		servicePort1 := rand.Intn(3000) + 6000
		serviceName := podName
		err = oc.Run("create").Args("service", "nodeport", serviceName, fmt.Sprintf("--tcp=%d:8080", servicePort1)).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("6) Check the service with the node ip and port %s", serviceName))
		nodePort, err := oc.Run("get").Args("services", serviceName, fmt.Sprintf("-o=jsonpath={.spec.ports[?(@.port==%d)].nodePort}", servicePort1)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodePort).NotTo(o.Equal(""))
		e2e.Logf("Get node port %s", nodePort)

		filename = "pod-for-ping.json"
		g.By(fmt.Sprintf("6.1) Create pod with resource file %s for checking network access", filename))
		template = getTestDataFilePath(filename)
		err = oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		podName = "pod-for-ping"
		g.By(fmt.Sprintf("6.2) Wait for pod with name %s to be ready", podName))
		assertPodToBeReady(oc, podName, namespace)

		if isIPv6(hostIP) {
			url = fmt.Sprintf("[%v]:%v", hostIP, nodePort)
		} else {
			url = fmt.Sprintf("%s:%s", hostIP, nodePort)
		}
		g.By(fmt.Sprintf("6.3) Accessing the endpoint %s with curl command line", url))
		err = wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 6*time.Second, false, func(cxt context.Context) (bool, error) {
			curlOutput, curlErr = oc.Run("exec").Args(podName, "-i", "--", "curl", url).Output()
			if curlErr != nil {
				return false, nil
			}
			return true, nil
		})
		assertWaitPollNoErr(err, fmt.Sprintf("Unable to access the %s", url))
		o.Expect(curlErr).NotTo(o.HaveOccurred())
		o.Expect(curlOutput).To(o.ContainSubstring("Hello OpenShift!"))

		g.By(fmt.Sprintf("6.4) Delete service %s", serviceName))
		err = oc.Run("delete").Args("service", serviceName).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		servicePort2 := rand.Intn(3000) + 6000
		npLeftBound, npRightBound := getNodePortRange(oc)
		g.By(fmt.Sprintf("7) Create another nodeport service with random target port %d and node port [%d-%d]", servicePort2, npLeftBound, npRightBound))
		generatedNodePort = rand.Intn(npRightBound-npLeftBound) + npLeftBound
		err1 := oc.Run("create").Args("service", "nodeport", serviceName, fmt.Sprintf("--node-port=%d", generatedNodePort), fmt.Sprintf("--tcp=%d:8080", servicePort2)).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())
		defer oc.Run("delete").Args("service", serviceName).Execute()

		if isIPv6(hostIP) {
			url = fmt.Sprintf("[%v]:%v", hostIP, generatedNodePort)
		} else {
			url = fmt.Sprintf("%s:%d", hostIP, generatedNodePort)
		}
		g.By(fmt.Sprintf("8) Check network access again to %s", url))
		err = wait.PollUntilContextTimeout(context.Background(), 2*time.Second, 6*time.Second, false, func(cxt context.Context) (bool, error) {
			curlOutput, curlErr = oc.Run("exec").Args(podName, "-i", "--", "curl", url).Output()
			if curlErr != nil {
				return false, nil
			}
			return true, nil
		})
		assertWaitPollNoErr(err, fmt.Sprintf("Unable to access the %s", url))
		o.Expect(curlErr).NotTo(o.HaveOccurred())
		o.Expect(curlOutput).To(o.ContainSubstring("Hello OpenShift!"))
	})

	g.It("Author:rgangwar-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-10970-[Apiserver] Create service with multiports", func() {
		var (
			filename  = "pod_with_multi_ports.json"
			filename1 = "pod-for-ping.json"
			podName1  = "hello-openshift"
			podName2  = "pod-for-ping"
		)

		g.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		g.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		g.By(fmt.Sprintf("2) Create pod with resource file %s", filename))
		template := getTestDataFilePath(filename)
		err := oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("3) Wait for pod with name %s to be ready", podName1))
		assertPodToBeReady(oc, podName1, namespace)

		g.By(fmt.Sprintf("4) Check host ip for pod %s", podName1))
		hostIP, err := oc.Run("get").Args("pods", podName1, "-o=jsonpath={.status.hostIP}", "-n", namespace).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(hostIP).NotTo(o.Equal(""))
		e2e.Logf("Get host ip %s", hostIP)

		g.By("5) Create nodeport service with random service port")
		servicePort1 := rand.Intn(3000) + 6000
		servicePort2 := rand.Intn(6001) + 9000

		serviceErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("service", "nodeport", podName1, fmt.Sprintf("--tcp=%d:8080,%d:8443", servicePort1, servicePort2), "-n", namespace).Execute()
		o.Expect(serviceErr).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("6) Check the service with the node port %s", podName1))
		nodePort1, err := oc.Run("get").Args("services", podName1, fmt.Sprintf("-o=jsonpath={.spec.ports[?(@.port==%d)].nodePort}", servicePort1)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodePort1).NotTo(o.Equal(""))
		nodePort2, err := oc.Run("get").Args("services", podName1, fmt.Sprintf("-o=jsonpath={.spec.ports[?(@.port==%d)].nodePort}", servicePort2)).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(nodePort2).NotTo(o.Equal(""))
		e2e.Logf("Get node port %s :: %s", nodePort1, nodePort2)

		g.By(fmt.Sprintf("6.1) Create pod with resource file %s for checking network access", filename1))
		template = getTestDataFilePath(filename1)
		err = oc.Run("create").Args("-f", template, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("6.2) Wait for pod with name %s to be ready", podName2))
		assertPodToBeReady(oc, podName2, namespace)

		g.By("6.3) Check URL endpoint access")
		checkURLEndpointAccess(oc, hostIP, nodePort1, podName2, "http", "hello-openshift http-8080")
		checkURLEndpointAccess(oc, hostIP, nodePort2, podName2, "https", "hello-openshift https-8443")

		g.By(fmt.Sprintf("6.4) Delete service %s", podName1))
		err = oc.Run("delete").Args("service", podName1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("7) Create another service with random target ports %d :: %d", servicePort1, servicePort2))
		err1 := oc.Run("create").Args("service", "clusterip", podName1, fmt.Sprintf("--tcp=%d:8080,%d:8443", servicePort1, servicePort2)).Execute()
		o.Expect(err1).NotTo(o.HaveOccurred())
		defer oc.Run("delete").Args("service", podName1).Execute()

		g.By(fmt.Sprintf("7.1) Check cluster ip for pod %s", podName1))
		clusterIP, serviceErr := oc.Run("get").Args("services", podName1, "-o=jsonpath={.spec.clusterIP}", "-n", namespace).Output()
		o.Expect(serviceErr).NotTo(o.HaveOccurred())
		o.Expect(clusterIP).ShouldNot(o.BeEmpty())
		e2e.Logf("Get node clusterIP :: %s", clusterIP)

		g.By("7.2) Check URL endpoint access again")
		checkURLEndpointAccess(oc, clusterIP, strconv.Itoa(servicePort1), podName2, "http", "hello-openshift http-8080")
		checkURLEndpointAccess(oc, clusterIP, strconv.Itoa(servicePort2), podName2, "https", "hello-openshift https-8443")
	})

	g.It("Author:rgangwar-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-11531-APIServer Can access both http and https pods and services via the API proxy [Serial]", func() {
		g.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		apiServerFQDN, _ := getApiServerFQDNandPort(oc)
		cmd := fmt.Sprintf(`nslookup %s`, apiServerFQDN)
		nsOutput, nsErr := exec.Command("bash", "-c", cmd).Output()
		if nsErr != nil {
			g.Skip(fmt.Sprintf("DNS resolution failed, case is not suitable for environment %s :: %s", nsOutput, nsErr))
		}

		g.By("1) Create a new project required for this test execution")
		oc.SetupProject()
		projectNs := oc.Namespace()

		g.By("2. Get the clustername")
		clusterName, clusterErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("view", "-o", `jsonpath={.clusters[0].name}`).Output()
		o.Expect(clusterErr).NotTo(o.HaveOccurred())
		e2e.Logf("Cluster Name :: %v", clusterName)

		g.By("3. Point to the API server referring the cluster name")
		apiserverName, apiErr := oc.AsAdmin().WithoutNamespace().Run("config").Args("view", "-o", `jsonpath={.clusters[?(@.name=="`+clusterName+`")].cluster.server}`).Output()
		o.Expect(apiErr).NotTo(o.HaveOccurred())
		e2e.Logf("Server Name :: %v", apiserverName)

		g.By("4) Get access token")
		token, err := oc.Run("whoami").Args("-t").Output()
		o.Expect(err).NotTo(o.HaveOccurred())

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
			g.By(fmt.Sprintf("%d.1) Build "+u.Target+" from external source", i+5))
			appErr := oc.AsAdmin().WithoutNamespace().Run("new-app").Args(u.URL, "-n", projectNs, "--import-mode=PreserveOriginal").Execute()
			o.Expect(appErr).NotTo(o.HaveOccurred())

			g.By(fmt.Sprintf("%d.2) Check if pod is properly running with expected status.", i+5))
			podsList := getPodsListByLabel(oc.AsAdmin(), projectNs, "deployment="+u.Target)
			assertPodToBeReady(oc, podsList[0], projectNs)

			g.By(fmt.Sprintf("%d.3) Perform the proxy GET request to resource REST endpoint with service", i+5))
			curlUrl := fmt.Sprintf(`%s/api/v1/namespaces/%s/services/http:%s:8080-tcp/proxy/`, apiserverName, projectNs, u.Target)
			output := clientCurl(token, curlUrl)
			o.Expect(output).Should(o.ContainSubstring(u.ExpectStr))

			g.By(fmt.Sprintf("%d.4) Perform the proxy GET request to resource REST endpoint with pod", i+5))
			curlUrl = fmt.Sprintf(`%s/api/v1/namespaces/%s/pods/http:%s:8080/proxy`, apiserverName, projectNs, podsList[0])
			output = clientCurl(token, curlUrl)
			o.Expect(output).Should(o.ContainSubstring(u.ExpectStr))
		}
	})

	g.It("Author:dpunia-ROSA-ARO-OSD_CCS-High-53085-Test Holes in EndpointSlice Validation Enable Host Network Hijack", func() {
		var (
			ns = "tmp53085"
		)

		defer oc.WithoutNamespace().AsAdmin().Run("delete").Args("ns", ns, "--ignore-not-found").Execute()
		err := oc.WithoutNamespace().AsAdmin().Run("create").Args("ns", ns).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("1) Check Holes in EndpointSlice Validation Enable Host Network Hijack")
		endpointSliceConfig := getTestDataFilePath("endpointslice.yaml")
		sliceCreateOut, sliceCreateError := oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", ns, "-f", endpointSliceConfig).Output()
		o.Expect(sliceCreateOut).Should(o.ContainSubstring(`Invalid value: "127.0.0.1": may not be in the loopback range`))
		o.Expect(sliceCreateError).To(o.HaveOccurred())
	})

	g.It("Author:dpunia-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-ConnectedOnly-High-53229-[Apiserver] Test Arbitrary path injection via type field in CNI configuration", func() {
		g.By("1) Create new project")
		oc.SetupProject()
		namespace := oc.Namespace()

		g.By("2) Create NetworkAttachmentDefinition with name nefarious-conf using nefarious.yaml")
		nefariousConfTemplate := getTestDataFilePath("ocp53229-nefarious.yaml")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-n", namespace, "-f", nefariousConfTemplate).Execute()
		nefariousConfErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", namespace, "-f", nefariousConfTemplate).Execute()
		o.Expect(nefariousConfErr).NotTo(o.HaveOccurred())

		g.By("3) Create Pod by using created NetworkAttachmentDefinition in annotations")
		nefariousPodTemplate := getTestDataFilePath("ocp53229-nefarious-pod.yaml")
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("-n", namespace, "-f", nefariousPodTemplate).Execute()
		nefariousPodErr := oc.AsAdmin().WithoutNamespace().Run("create").Args("-n", namespace, "-f", nefariousPodTemplate).Execute()
		o.Expect(nefariousPodErr).NotTo(o.HaveOccurred())

		g.By("4) Check pod should be in creating or failed status and event should show error message invalid plugin")
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
		assertWaitPollNoErr(err, "Detected event CNI network invalid plugin")

		g.By("5) Check pod created on node should not be rebooting and appear offline")
		nodeName, nodeErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("-n", namespace, "-f", nefariousPodTemplate, "-o", "jsonpath={.spec.nodeName}").Output()
		o.Expect(nodeErr).NotTo(o.HaveOccurred())
		nodeStatus, nodeStatusErr := oc.AsAdmin().WithoutNamespace().Run("get").Args("node", nodeName, "--no-headers").Output()
		o.Expect(nodeStatusErr).NotTo(o.HaveOccurred())
		o.Expect(nodeStatus).Should(o.ContainSubstring("Ready"))
	})
})
