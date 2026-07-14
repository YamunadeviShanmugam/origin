package apiserver

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

var _ = g.Describe("[sig-api-machinery][Feature:APIServer] API_Server Quota", func() {
	defer g.GinkgoRecover()

	oc := exutil.NewCLI("apiserver-quota")

	g.It("Author:kewang-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-Longduration-NonPreRelease-Medium-12308-Customizing template for project creation [Serial][Slow]", func() {
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

		g.By("1) Create a bootstrap project template and output it to a file template.yaml")
		_, err = oc.AsAdmin().WithoutNamespace().Run("adm").Args("create-bootstrap-project-template", "-o", "yaml").OutputToFile(filepath.Join(caseID, templateYaml))
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("2) To customize template.yaml and add ResourceQuota and LimitRange objects.")
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

		sedCmd := fmt.Sprintf(`sed -i '/^parameters:/e cat %s' %s`, patchYamlFile, templateYamlFile)
		e2e.Logf("Check sed cmd %s description:", sedCmd)
		_, err = exec.Command("bash", "-c", sedCmd).Output()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3) Create a project request template from the customized template.yaml file in the openshift-config namespace.")
		err = oc.AsAdmin().WithoutNamespace().Run("create").Args("-f", templateYamlFile, "-n", "openshift-config").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("templates", "project-request", "-n", "openshift-config").Execute()

		g.By("4) Create new project before applying the customized template of projects.")
		err = oc.AsAdmin().WithoutNamespace().Run("new-project").Args(project1).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("project", project1).Execute()

		g.By("5) Associate the template with projectRequestTemplate in the project resource of the config.openshift.io/v1.")
		err = oc.AsAdmin().WithoutNamespace().Run("patch").Args("project.config.openshift.io/cluster", "--type=json", "-p", patchJSON).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer func() {
			oc.AsAdmin().WithoutNamespace().Run("patch").Args("project.config.openshift.io/cluster", "--type=json", "-p", restorePatchJSON).Execute()
			expectedStatus := map[string]string{"Progressing": "True"}
			err = waitCoBecomes(oc, "openshift-apiserver", 240, expectedStatus)
			assertWaitPollNoErr(err, `openshift-apiserver status has not yet changed to {"Progressing": "True"} in 240 seconds`)
			expectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
			err = waitCoBecomes(oc, "openshift-apiserver", 360, expectedStatus)
			assertWaitPollNoErr(err, `openshift-apiserver operator status has not yet changed to {"Available": "True", "Progressing": "False", "Degraded": "False"} in 360 seconds`)
			e2e.Logf("openshift-apiserver pods are all running.")
		}()

		g.By("5.1) Wait until the openshift-apiserver clusteroperator complete degradation and in the normal status ...")
		expectedStatus := map[string]string{"Progressing": "True"}
		err = waitCoBecomes(oc, "openshift-apiserver", 240, expectedStatus)
		assertWaitPollNoErr(err, `openshift-apiserver status has not yet changed to {"Progressing": "True"} in 240 seconds`)
		expectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
		err = waitCoBecomes(oc, "openshift-apiserver", 360, expectedStatus)
		assertWaitPollNoErr(err, `openshift-apiserver operator status has not yet changed to {"Available": "True", "Progressing": "False", "Degraded": "False"} in 360 seconds`)
		e2e.Logf("openshift-apiserver operator is normal and pods are all running.")

		g.By("6) The resource quotas will be used for a new project after the customized template of projects is applied.")
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

		g.By("7) To add applications to created project, check if Quota usage of the project is changed.")
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
		assertWaitPollNoErr(err, "Some of pods still not get ready!")

		output, err = oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", project2).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Check quotas changes of project %s after new app is created:", project2)
		for _, regx := range regexpr {
			o.Expect(string(output)).Should(o.MatchRegexp(regx))
		}

		g.By("8) Check the previously created project, no quotas setting is applied.")
		output, err = oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", project1).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Check quotas changes of project %s after new app is created:", project1)
		o.Expect(string(output)).NotTo(o.ContainSubstring(project1 + "-quota"))
		o.Expect(string(output)).NotTo(o.ContainSubstring(project1 + "-limits"))

		g.By("9) After deleted all resource objects for created application, the quota usage of the project is released.")
		err = oc.AsAdmin().WithoutNamespace().Run("delete").Args("all", "--selector", "app=hello-openshift").Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 60*time.Second, false, func(cxt context.Context) (bool, error) {
			output, _ := oc.WithoutNamespace().Run("get").Args("all").Output()
			if matched, _ := regexp.MatchString("No resources found.*", output); matched {
				e2e.Logf("All resource objects for created application have been completely deleted\n%s", output)
				return true, nil
			}
			return false, nil
		})
		assertWaitPollNoErr(err, "All resource objects for created application haven't been completely deleted!")

		output, err = oc.AsAdmin().WithoutNamespace().Run("describe").Args("project", project2).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		e2e.Logf("Check quotas setting of project %s description:", project2)
		for _, regx := range initRegExpr {
			o.Expect(string(output)).Should(o.MatchRegexp(regx))
		}
	})

	g.It("Author:zxiao-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-Medium-12360-[origin_platformexp_403] The number of created API objects can not exceed quota limitation", func() {
		g.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()
		limit := 3

		g.By("2) Get quota limits according to used resource count under namespace")
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
		limits.resourcequotaLimit += limit + 1

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
		g.By(fmt.Sprintf("3) Create quota with resource file %s", filename))
		template := getTestDataFilePath(filename)
		params := []string{"-f", template, "-p", fmt.Sprintf("POD_LIMIT=%d", limits.podLimit), fmt.Sprintf("RQ_LIMIT=%d", limits.resourcequotaLimit), fmt.Sprintf("SECRET_LIMIT=%d", limits.secretLimit), fmt.Sprintf("SERVICE_LIMIT=%d", limits.serviceLimit), fmt.Sprintf("CM_LIMIT=%d", limits.configmapLimit), fmt.Sprintf("NAME=%s", quotaName)}
		configFile := processTemplate(oc, params...)
		err = oc.AsAdmin().Run("create").Args("-f", configFile, "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("4) Wait for quota to show up in command describe")
		quotaDescribeErr := wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 20*time.Second, false, func(cxt context.Context) (bool, error) {
			describeOutput, err := oc.Run("describe").Args("quota", quotaName, "-n", namespace).Output()
			if isMatched, matchErr := regexp.Match("secrets.*[0-9]", []byte(describeOutput)); isMatched && matchErr == nil && err == nil {
				return true, nil
			}
			return false, nil
		})
		assertWaitPollNoErr(quotaDescribeErr, "quota did not show up")

		g.By("5) Create multiple secrets, expect failure for secret creations that exceed quota limit")
		for i := 1; i <= limit+1; i++ {
			secretName := fmt.Sprintf("ocp12360-secret-%d", i)
			output, err := oc.Run("create").Args("secret", "generic", secretName, "--from-literal=testkey=testvalue", "-n", namespace).Output()
			if i <= limit {
				g.By(fmt.Sprintf("5.%d) creating secret %s, within quota limit, expect success", i, secretName))
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				g.By(fmt.Sprintf("5.%d) creating secret %s, exceeds quota limit, expect failure", i, secretName))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("secrets.*forbidden: exceeded quota"))
			}
		}

		filename = "ocp12360-pod.yaml"
		g.By(fmt.Sprintf("6) Create multiple pods, expect failure for pod creations that exceed quota limit"))
		template = getTestDataFilePath(filename)
		for i := 1; i <= limit+1; i++ {
			podName := fmt.Sprintf("ocp12360-pod-%d", i)
			configFile := processTemplate(oc, "-f", template, "-p", "NAME="+podName)
			output, err := oc.Run("create").Args("-f", configFile, "-n", namespace).Output()
			if i <= limit {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("pods.*forbidden: exceeded quota"))
			}
		}

		g.By("7) Create multiple services, expect failure for service creations that exceed quota limit")
		for i := 1; i <= limit+1; i++ {
			serviceName := fmt.Sprintf("ocp12360-service-%d", i)
			externalName := fmt.Sprintf("ocp12360-external-name-%d", i)
			output, err := oc.Run("create").Args("service", "externalname", serviceName, "-n", namespace, "--external-name", externalName).Output()
			if i <= limit {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("services.*forbidden: exceeded quota"))
			}
		}

		filename = "ocp12360-quota.yaml"
		g.By("8) Create multiple quotas, expect failure for quota creations that exceed quota limit")
		template = getTestDataFilePath(filename)
		for i := 1; i <= limit+1; i++ {
			quotaName := fmt.Sprintf("ocp12360-quota-%d", i)
			params := []string{"-f", template, "-p", fmt.Sprintf("POD_LIMIT=%d", limits.podLimit), fmt.Sprintf("RQ_LIMIT=%d", limits.resourcequotaLimit), fmt.Sprintf("SECRET_LIMIT=%d", limits.secretLimit), fmt.Sprintf("SERVICE_LIMIT=%d", limits.serviceLimit), fmt.Sprintf("CM_LIMIT=%d", limits.configmapLimit), fmt.Sprintf("NAME=%s", quotaName)}
			configFile := processTemplate(oc, params...)
			output, err := oc.AsAdmin().Run("create").Args("-f", configFile, "-n", namespace).Output()
			if i <= limit {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("resourcequotas.*forbidden: exceeded quota"))
			}
		}

		g.By("9) Create multiple configmaps, expect failure for configmap creations that exceed quota limit")
		for i := 1; i <= limit+1; i++ {
			configmapName := fmt.Sprintf("ocp12360-configmap-%d", i)
			output, err := oc.Run("create").Args("configmap", configmapName, "-n", namespace).Output()
			if i <= limit {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(output).To(o.MatchRegexp("configmaps.*forbidden: exceeded quota"))
			}
		}
	})

	g.It("Author:dpunia-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-PreChkUpgrade-NonPreRelease-High-54745-Bug clusterResourceQuota objects check", func() {
		var (
			caseID           = "ocp-54745"
			namespace        = caseID + "-quota-test"
			clusterQuotaName = caseID + "-crq-test"
			crqLimits        = map[string]string{
				"pods":                                  "4",
				"secrets":                               "10",
				"cpu":                                   "7",
				"memory":                                "5Gi",
				"requests.cpu":                          "6",
				"requests.memory":                       "6Gi",
				"limits.cpu":                            "6",
				"limits.memory":                         "6Gi",
				"configmaps":                            "5",
				"count/deployments.apps":                "1",
				"count/templates.template.openshift.io": "3",
				"count/servicemonitors.monitoring.coreos.com": "1",
			}
		)

		g.By("1) Create custom project for Pre & Post Upgrade ClusterResourceQuota test.")
		nsError := oc.WithoutNamespace().AsAdmin().Run("create").Args("ns", namespace).Execute()
		o.Expect(nsError).NotTo(o.HaveOccurred())

		g.By("2) Create resource ClusterResourceQuota")
		err := oc.WithoutNamespace().AsAdmin().Run("create").Args("-n", namespace, "-f", getTestDataFilePath("clusterresourcequota.yaml")).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		params := []string{"-n", namespace, "clusterresourequotaremplate", "-p",
			"NAME=" + clusterQuotaName,
			"LABEL=" + namespace,
			"PODS_LIMIT=" + crqLimits["pods"],
			"SECRETS_LIMIT=" + crqLimits["secrets"],
			"CPU_LIMIT=" + crqLimits["cpu"],
			"MEMORY_LIMIT=" + crqLimits["memory"],
			"REQUESTS_CPU=" + crqLimits["requests.cpu"],
			"REQUEST_MEMORY=" + crqLimits["requests.memory"],
			"LIMITS_CPU=" + crqLimits["limits.cpu"],
			"LIMITS_MEMORY=" + crqLimits["limits.memory"],
			"CONFIGMAPS_LIMIT=" + crqLimits["configmaps"],
			"TEMPLATE_COUNT=" + crqLimits["count/templates.template.openshift.io"],
			"SERVICE_MONITOR=" + crqLimits["count/servicemonitors.monitoring.coreos.com"],
			"DEPLOYMENT=" + crqLimits["count/deployments.apps"]}
		quotaConfigFile := processTemplate(oc, params...)
		err = oc.WithoutNamespace().AsAdmin().Run("create").Args("-n", namespace, "-f", quotaConfigFile).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By("3) Create multiple secrets to test created ClusterResourceQuota")
		createSecretsWithQuotaValidation(oc, namespace, clusterQuotaName, crqLimits, caseID)

		g.By("4) Create few pods before upgrade to check ClusterResourceQuota")
		podsCount, err := oc.Run("get").Args("-n", namespace, "clusterresourcequota", clusterQuotaName, "-o", `jsonpath={.status.namespaces[*].status.used.pods}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		existingPodCount, _ := strconv.Atoi(podsCount)
		limits, _ := strconv.Atoi(crqLimits["pods"])
		podTemplate := getTestDataFilePath("ocp54745-pod.yaml")
		for i := existingPodCount; i < limits-2; i++ {
			podname := fmt.Sprintf("%v-pod-%d", caseID, i)
			params := []string{"-n", namespace, "-f", podTemplate, "-p", "NAME=" + podname, "REQUEST_MEMORY=1Gi", "REQUEST_CPU=1", "LIMITS_MEMORY=1Gi", "LIMITS_CPU=1"}
			podConfigFile := processTemplate(oc, params...)
			err = oc.AsAdmin().WithoutNamespace().Run("-n", namespace, "create").Args("-f", podConfigFile).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())
		}

		g.By("5) Create new app & Service Monitor to check quota exceeded")
		err = oc.WithoutNamespace().AsAdmin().Run("create").Args("-n", namespace, "-f", getTestDataFilePath("service-monitor.yaml")).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		for count := 1; count < 3; count++ {
			appName := fmt.Sprintf("%v-app-%v", caseID, count)
			image := "quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83"
			output, err := oc.AsAdmin().WithoutNamespace().Run("new-app").Args(fmt.Sprintf("--name=%v", appName), image, "-n", namespace).Output()
			if count <= limits {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(output).To(o.MatchRegexp("deployments.apps.*forbidden: exceeded quota"))
			}

			params = []string{"-n", namespace, "servicemonitortemplate", "-p",
				fmt.Sprintf("NAME=%v-service-monitor-%v", caseID, count),
				"DEPLOYMENT=" + crqLimits["count/deployments.apps"],
			}
			serviceMonitor := processTemplate(oc, params...)
			output, err = oc.WithoutNamespace().AsAdmin().Run("create").Args("-n", namespace, "-f", serviceMonitor).Output()
			limits, _ = strconv.Atoi(crqLimits["count/servicemonitors.monitoring.coreos.com"])
			if count <= limits {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(output).To(o.MatchRegexp("servicemonitors.*forbidden: exceeded quota"))
			}
		}

		g.By("6) Compare applied ClusterResourceQuota")
		for resourceName, limit := range crqLimits {
			resource, err := oc.Run("get").Args("-n", namespace, "clusterresourcequota", clusterQuotaName, "-o", fmt.Sprintf(`jsonpath={.status.namespaces[*].status.used.%v}`, strings.ReplaceAll(resourceName, ".", "\\."))).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			usedResource, _ := strconv.Atoi(strings.Trim(resource, "Gi"))
			limitVal, _ := strconv.Atoi(strings.Trim(limit, "Gi"))
			if 0 < usedResource && usedResource <= limitVal {
				e2e.Logf("Test Passed: ClusterResourceQuota for Resource %v is in applied limit", resourceName)
			} else {
				e2e.Failf("Test Failed: ClusterResourceQuota for Resource %v is not in applied limit", resourceName)
			}
		}
	})

	g.It("Author:dpunia-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-PstChkUpgrade-NonPreRelease-High-54745-Bug clusterResourceQuota objects check", func() {
		var (
			caseID           = "ocp-54745"
			namespace        = caseID + "-quota-test"
			clusterQuotaName = caseID + "-crq-test"
			crqLimits        = map[string]string{
				"pods":           "4",
				"secrets":        "10",
				"cpu":            "7",
				"memory":         "5Gi",
				"requestsCpu":    "6",
				"requestsMemory": "6Gi",
				"limitsCpu":      "6",
				"limitsMemory":   "6Gi",
				"configmaps":     "5",
			}
		)

		defer oc.AsAdmin().WithoutNamespace().Run("delete", "project").Args(namespace).Execute()
		defer oc.WithoutNamespace().AsAdmin().Run("delete").Args("-n", namespace, "clusterresourcequota", clusterQuotaName).Execute()

		g.By("6) Create pods after upgrade to check ClusterResourceQuota")
		podsCount, err := oc.Run("get").Args("-n", namespace, "clusterresourcequota", clusterQuotaName, "-o", `jsonpath={.status.namespaces[*].status.used.pods}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		existingPodCount, _ := strconv.Atoi(podsCount)
		limits, _ := strconv.Atoi(crqLimits["pods"])
		podTemplate := getTestDataFilePath("ocp54745-pod.yaml")
		for i := existingPodCount; i <= limits; i++ {
			podname := fmt.Sprintf("%v-pod-%d", caseID, i)
			params := []string{"-n", namespace, "-f", podTemplate, "-p", "NAME=" + podname, "REQUEST_MEMORY=1Gi", "REQUEST_CPU=1", "LIMITS_MEMORY=1Gi", "LIMITS_CPU=1"}
			podConfigFile := processTemplate(oc, params...)
			output, err := oc.AsAdmin().WithoutNamespace().Run("-n", namespace, "create").Args("-f", podConfigFile).Output()
			g.By(fmt.Sprintf("5.%d) creating pod %s", i, podname))
			if i < limits {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(output).To(o.MatchRegexp("pods.*forbidden: exceeded quota"))
			}
		}

		g.By("7) Create multiple configmap to test created ClusterResourceQuota")
		cmCount, err := oc.Run("get").Args("-n", namespace, "clusterresourcequota", clusterQuotaName, "-o", `jsonpath={.status.namespaces[*].status.used.configmaps}`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		cmUsedCount, _ := strconv.Atoi(cmCount)
		limits, _ = strconv.Atoi(crqLimits["configmaps"])
		for i := cmUsedCount; i <= limits; i++ {
			configmapName := fmt.Sprintf("%v-configmap-%d", caseID, i)
			output, err := oc.Run("create").Args("-n", namespace, "configmap", configmapName).Output()
			g.By(fmt.Sprintf("7.%d) creating configmap %s", i, configmapName))
			if i < limits {
				o.Expect(err).NotTo(o.HaveOccurred())
			} else {
				o.Expect(output).To(o.MatchRegexp("configmaps.*forbidden: exceeded quota"))
			}
		}

		g.By("8) Compare applied ClusterResourceQuota")
		for _, resourceName := range []string{"pods", "secrets", "cpu", "memory", "configmaps"} {
			resource, err := oc.Run("get").Args("-n", namespace, "clusterresourcequota", clusterQuotaName, "-o", fmt.Sprintf(`jsonpath={.status.namespaces[*].status.used.%v}`, resourceName)).Output()
			o.Expect(err).NotTo(o.HaveOccurred())
			usedResource, _ := strconv.Atoi(strings.Trim(resource, "mGi"))
			limitVal, _ := strconv.Atoi(strings.Trim(crqLimits[resourceName], "mGi"))
			if 0 < usedResource && usedResource <= limitVal {
				e2e.Logf("Test Passed: ClusterResourceQuota for Resource %v is in applied limit", resourceName)
			} else {
				e2e.Failf("Test Failed: ClusterResourceQuota for Resource %v is not in applied limit", resourceName)
			}
		}
	})

	g.It("Author:kewang-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-11289-[Apiserver] Check the imagestreams of quota in the project after build image [Serial]", func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		var (
			caseID        = "ocp-11289"
			dirname       = "/tmp/-" + caseID
			expectedQuota = "openshift.io/imagestreams:2"
		)

		err := os.MkdirAll(dirname, 0755)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(dirname)

		g.By("1) Create a new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		g.By("2) Create a ResourceQuota count of image stream")
		ocpObjectCountsYamlFile := dirname + "/openshift-object-counts.yaml"
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

		g.By("3. Checking the created Resource Quota of the Image Stream")
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
			assertWaitPollNoErr(buildErr, fmt.Sprintf("ERROR: Build status of %s is not complete!", buildName))

			g.By(fmt.Sprintf("%s.1 Checking the created Resource Quota of the Image Stream", step))
			quota := getResourceToBeReady(oc, asAdmin, withoutNamespace, "quota", "openshift-object-counts", `--template={{.status.used}}`, "-n", namespace)

			if !strings.Contains(quota, expectedQuota) {
				out, _ := getResource(oc, asAdmin, withoutNamespace, "imagestream", "-n", namespace)
				e2e.Logf("imagestream are used: %s", out)
				e2e.Failf("expected quota openshift-object-counts %s doesn't match the reality %s! Please check!", expectedQuota, quota)
			}
		}

		g.By("4. Create a source build using source code and check the build info")
		imgErr := oc.AsAdmin().WithoutNamespace().Run("new-build").Args(`quay.io/openshifttest/ruby-27:1.2.0~https://github.com/sclorg/ruby-ex.git`, "-n", namespace, "--import-mode=PreserveOriginal").Execute()
		o.Expect(imgErr).NotTo(o.HaveOccurred())
		checkImageStreamQuota("ruby-ex-1", "4")

		g.By("5. Starts a new build for the provided build config")
		sbErr := oc.AsAdmin().WithoutNamespace().Run("start-build").Args("ruby-ex", "-n", namespace).Execute()
		o.Expect(sbErr).NotTo(o.HaveOccurred())
		checkImageStreamQuota("ruby-ex-2", "5")
	})
})
