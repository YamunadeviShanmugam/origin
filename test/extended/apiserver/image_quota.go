package apiserver

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"

	exutil "github.com/openshift/origin/test/extended/util"
	"k8s.io/apimachinery/pkg/util/wait"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

var _ = g.Describe("[sig-api-machinery][Feature:APIServer] API_Server Image Quota", func() {
	defer g.GinkgoRecover()

	oc := exutil.NewCLI("apiserver-image-quota")

	g.It("Author:kewang-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-11797-[Apiserver] Image with single or multiple layer(s) sumed up size slightly exceed the openshift.io/image-size will push failed", func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig") && isEnabledCapability(oc, "ImageRegistry")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		g.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		tmpdir, err := os.MkdirTemp("", "ocp-11797-")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(tmpdir)

		var (
			imageLimitRangeYamlFile = tmpdir + "/image-limit-range.yaml"
			imageLimitRangeYaml     = fmt.Sprintf(`apiVersion: v1
kind: LimitRange
metadata:
  name: openshift-resource-limits
spec:
  limits:
    - type: openshift.io/Image
      max:
        storage: %s
    - type: openshift.io/ImageStream
      max:
        openshift.io/image-tags: 20
        openshift.io/images: 30
`, "100Mi")
		)

		g.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()

		g.By("2) Create a resource quota limit of the image")
		f, err := os.Create(imageLimitRangeYamlFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = w.WriteString(imageLimitRangeYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		defer oc.AsAdmin().Run("delete").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
		quotaErr := oc.AsAdmin().Run("create").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
		o.Expect(quotaErr).NotTo(o.HaveOccurred())

		g.By(`3) Using "skopeo" tool to copy image from quay registry to the default internal registry of the cluster`)
		destRegistry := "docker://" + defaultRegistryServiceURL + "/" + namespace + "/mystream:latest"

		g.By(`3.1) Try copying multiple layers image to the default internal registry of the cluster`)
		publicImageUrl := "docker://" + "quay.io/openshifttest/mysql:1.2.0"
		var output string
		errPoll := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 200*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err = copyImageToInternalRegistry(oc, namespace, publicImageUrl, destRegistry)
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
			assertWaitPollNoErr(errPoll, "Failed to retrieve")
		}

		g.By(`3.2) Try copying single layer image to the default internal registry of the cluster`)
		publicImageUrl = "docker://" + "quay.io/openshifttest/singlelayer:latest"
		errPoll = wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 200*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err = copyImageToInternalRegistry(oc, namespace, publicImageUrl, destRegistry)
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
			assertWaitPollNoErr(errPoll, "Failed to retrieve")
		}
	})

	g.It("Author:rgangwar-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-10865-[Apiserver] After Image Size Limit increment can push the image which previously over the limit", func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig") && isEnabledCapability(oc, "ImageRegistry")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		g.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		tmpdir, err := os.MkdirTemp("", "ocp-10865-")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(tmpdir)

		imageLimitRangeYamlFile := tmpdir + "/image-limit-range.yaml"

		g.By("1) Create new project required for this test execution")
		oc.SetupProject()
		namespace := oc.Namespace()
		defer oc.AsAdmin().Run("delete").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()

		for i, storage := range []string{"16Mi", "1Gi"} {
			imageLimitRangeYaml := fmt.Sprintf(`apiVersion: v1
kind: LimitRange
metadata:
  name: openshift-resource-limits
spec:
  limits:
    - type: openshift.io/Image
      max:
        storage: %s
    - type: openshift.io/ImageStream
      max:
        openshift.io/image-tags: 20
        openshift.io/images: 30
`, storage)

			g.By(fmt.Sprintf("%d.1) Create a resource quota limit of the image with storage limit %s", i+1, storage))
			f, err := os.Create(imageLimitRangeYamlFile)
			o.Expect(err).NotTo(o.HaveOccurred())
			defer f.Close()
			w := bufio.NewWriter(f)
			_, err = w.WriteString(imageLimitRangeYaml)
			w.Flush()
			o.Expect(err).NotTo(o.HaveOccurred())

			var action string
			if storage == "16Mi" {
				action = "create"
			} else if storage == "1Gi" {
				action = "replace"
			}

			quotaErr := oc.AsAdmin().Run(action).Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
			o.Expect(quotaErr).NotTo(o.HaveOccurred())

			g.By(fmt.Sprintf(`%d.2) Using "skopeo" tool to copy image from quay registry to the default internal registry of the cluster`, i+1))
			destRegistry := "docker://" + defaultRegistryServiceURL + "/" + namespace + "/mystream:latest"

			g.By(fmt.Sprintf(`%d.3) Try copying image to the default internal registry of the cluster`, i+1))
			publicImageUrl := "docker://quay.io/openshifttest/base-alpine@sha256:3126e4eed4a3ebd8bf972b2453fa838200988ee07c01b2251e3ea47e4b1f245c"
			var output string
			errPoll := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
				output, err = copyImageToInternalRegistry(oc, namespace, publicImageUrl, destRegistry)
				if err != nil {
					if strings.Contains(output, "denied") {
						o.Expect(strings.Contains(output, "denied")).Should(o.BeTrue(), "Should deny copying"+publicImageUrl)
						return true, nil
					}
				} else if err == nil {
					return true, nil
				}
				return false, nil
			})
			if errPoll != nil {
				e2e.Logf("Failed to retrieve %v", output)
				assertWaitPollNoErr(errPoll, "Failed to retrieve")
			}
		}
	})

	g.It("Author:rgangwar-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-12263-[Apiserver] When exceed openshift.io/images will ban to create image reference or push image to project", func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig") && isEnabledCapability(oc, "ImageRegistry")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		g.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		tmpdir, err := os.MkdirTemp("", "ocp-12263-")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(tmpdir)

		var (
			imageLimitRangeYamlFile = tmpdir + "/image-limit-range.yaml"
			imageName1              = `quay.io/openshifttest/base-alpine@sha256:3126e4eed4a3ebd8bf972b2453fa838200988ee07c01b2251e3ea47e4b1f245c`
			imageName2              = `quay.io/openshifttest/hello-openshift:1.2.0`
			imageName3              = `quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83`
			imageStreamErr          error
		)

		g.By("1) Create new project required for this test execution")
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

		g.By("2) Create a resource quota limit of the image with images limit 1")
		f, err := os.Create(imageLimitRangeYamlFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = w.WriteString(imageLimitRangeYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		quotaErr := oc.AsAdmin().Run("create").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
		o.Expect(quotaErr).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("3.) Applying a mystream:v1 image tag to %s in an image stream should succeed", imageName1))
		tagErr := oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName1, "--source=docker", "mystream:v1", "-n", namespace).Execute()
		o.Expect(tagErr).NotTo(o.HaveOccurred())

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
		assertWaitPollNoErr(errImage, fmt.Sprintf("Image is tag with v1 is not successfull %s", imageStreamErr))

		g.By(fmt.Sprintf("4.) Applying the mystream:v2 image tag to another %s in an image stream should fail due to the ImageStream max images limit", imageName2))
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
		assertWaitPollNoErr(errImageV2, fmt.Sprintf("Image is tag with v2 is successfull %s", imageStreamv2Err))

		g.By(`5.) Copying an image to the default internal registry of the cluster should be denied due to the max storage size limit for images`)
		destRegistry := "docker://" + defaultRegistryServiceURL + "/" + namespace + "/mystream:latest"
		publicImageUrl := "docker://" + imageName3
		var output string
		errPoll := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err = copyImageToInternalRegistry(oc, namespace, publicImageUrl, destRegistry)
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
			assertWaitPollNoErr(errPoll, "Failed to retrieve")
		}
	})

	g.It("Author:rgangwar-ROSA-ARO-OSD_CCS-ConnectedOnly-Medium-12158-[Apiserver] Specify ResourceQuota on project", func() {
		if isBaselineCapsSet(oc) && !(isEnabledCapability(oc, "Build") && isEnabledCapability(oc, "DeploymentConfig") && isEnabledCapability(oc, "ImageRegistry")) {
			g.Skip("Skipping the test as baselinecaps have been set and some of API capabilities are not enabled!")
		}

		g.By("Check if it's a proxy cluster")
		httpProxy, httpsProxy, _ := getGlobalProxy(oc)
		if strings.Contains(httpProxy, "http") || strings.Contains(httpsProxy, "https") {
			g.Skip("Skip for proxy platform")
		}

		tmpdir, err := os.MkdirTemp("", "ocp-12158-")
		o.Expect(err).NotTo(o.HaveOccurred())
		defer os.RemoveAll(tmpdir)

		var (
			imageLimitRangeYamlFile = tmpdir + "/image-limit-range.yaml"
			imageName1              = `quay.io/openshifttest/base-alpine@sha256:3126e4eed4a3ebd8bf972b2453fa838200988ee07c01b2251e3ea47e4b1f245c`
			imageName2              = `quay.io/openshifttest/hello-openshift:1.2.0`
			imageName3              = `quay.io/openshifttest/hello-openshift@sha256:4200f438cf2e9446f6bcff9d67ceea1f69ed07a2f83363b7fb52529f7ddd8a83`
			imageStreamErr          error
		)

		g.By("1) Create new project required for this test execution")
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

		g.By("2) Create a resource quota limit of the imagestream with limit 1")
		f, err := os.Create(imageLimitRangeYamlFile)
		o.Expect(err).NotTo(o.HaveOccurred())
		defer f.Close()
		w := bufio.NewWriter(f)
		_, err = w.WriteString(imageLimitRangeYaml)
		w.Flush()
		o.Expect(err).NotTo(o.HaveOccurred())

		quotaErr := oc.AsAdmin().Run("create").Args("-f", imageLimitRangeYamlFile, "-n", namespace).Execute()
		o.Expect(quotaErr).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("3.) Applying a mystream:v1 image tag to %s in an image stream should succeed", imageName1))
		tagErr := oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName1, "--source=docker", "mystream:v1", "-n", namespace).Execute()
		o.Expect(tagErr).NotTo(o.HaveOccurred())

		errImage := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 300*time.Second, false, func(cxt context.Context) (bool, error) {
			imageStreamOutput, imageStreamErr := oc.AsAdmin().WithoutNamespace().Run("describe").Args("imagestream", "mystream", "-n", namespace).Output()
			if imageStreamErr == nil {
				if strings.Contains(imageStreamOutput, imageName1) {
					return true, nil
				}
			}
			return false, nil
		})
		assertWaitPollNoErr(errImage, fmt.Sprintf("Image tagging with v1 is not successful %s", imageStreamErr))

		g.By(fmt.Sprintf("4.) Applying the mystream2:v1 image tag to another %s in an image stream should fail due to the ImageStream max limit", imageName2))
		output, tagErr := oc.AsAdmin().WithoutNamespace().Run("tag").Args(imageName2, "--source=docker", "mystream2:v1", "-n", namespace).Output()
		o.Expect(tagErr).To(o.HaveOccurred())
		o.Expect(string(output)).To(o.MatchRegexp("forbidden: [Ee]xceeded quota"))

		g.By(`5.) Copying an image to the default internal registry of the cluster should be denied due to the max imagestream limit for images`)
		destRegistry := "docker://" + defaultRegistryServiceURL + "/" + namespace + "/mystream3"
		publicImageUrl := "docker://" + imageName3
		errPoll := wait.PollUntilContextTimeout(context.Background(), 10*time.Second, 120*time.Second, false, func(cxt context.Context) (bool, error) {
			output, err = copyImageToInternalRegistry(oc, namespace, publicImageUrl, destRegistry)
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
			assertWaitPollNoErr(errPoll, "Failed to retrieve")
		}
	})

	g.It("Author:rgangwar-NonHyperShiftHOST-ROSA-ARO-OSD_CCS-Longduration-NonPreRelease-ConnectedOnly-Medium-68400-[Apiserver] Do not generate image pull secrets for internal registry when internal registry is disabled[Slow][Disruptive]", func() {
		var (
			namespace    = "ocp-68400"
			secretOutput string
			dockerOutput string
			currentStep  = 2
		)

		err := oc.AsAdmin().WithoutNamespace().Run("create").Args("ns", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		defer oc.AsAdmin().WithoutNamespace().Run("delete").Args("ns", namespace, "--ignore-not-found").Execute()

		g.By("1. Check Image registry's enabled")
		output, err := oc.WithoutNamespace().AsAdmin().Run("get").Args("configs.imageregistry.operator.openshift.io/cluster", "-o", `jsonpath='{.spec.managementState}'`).Output()
		o.Expect(err).NotTo(o.HaveOccurred())
		if strings.Contains(output, "Managed") {
			g.By(fmt.Sprintf("%v. Create serviceAccount test-a", currentStep))
			err = oc.WithoutNamespace().AsAdmin().Run("create").Args("sa", "test-a", "-n", namespace).Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By(fmt.Sprintf("%v. Check if Token and Dockercfg Secrets of SA test-a are created.", currentStep+1))
			secretOutput = getResourceToBeReady(oc, asAdmin, withoutNamespace, "secrets", "-n", namespace, "-o", "jsonpath='{range .items[*]}{.metadata.name}{\" \"}'")
			o.Expect(string(secretOutput)).To(o.ContainSubstring("test-a-dockercfg-"))

			g.By(fmt.Sprintf("%v. Disable the Internal Image Registry", currentStep+2))
			defer func() {
				g.By("Recovering Internal image registry")
				output, err := oc.WithoutNamespace().AsAdmin().Run("patch").Args("configs.imageregistry/cluster", "-p", `{"spec":{"managementState":"Managed"}}`, "--type=merge").Output()
				o.Expect(err).NotTo(o.HaveOccurred())
				if strings.Contains(output, "patched (no change)") {
					e2e.Logf("No changes to the internal image registry.")
				} else {
					g.By("Waiting KAS and Image registry reboot after the Internal Image Registry was enabled")
					e2e.Logf("Checking kube-apiserver operator should be in Progressing in 100 seconds")
					expectedStatus := map[string]string{"Progressing": "True"}
					err = waitCoBecomes(oc, "kube-apiserver", 100, expectedStatus)
					assertWaitPollNoErr(err, "kube-apiserver operator is not start progressing in 100 seconds")
					e2e.Logf("Checking kube-apiserver operator should be Available in 1500 seconds")
					expectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
					err = waitCoBecomes(oc, "kube-apiserver", 1500, expectedStatus)
					assertWaitPollNoErr(err, "kube-apiserver operator is not becomes available in 1500 seconds")
					err = waitCoBecomes(oc, "image-registry", 100, expectedStatus)
					assertWaitPollNoErr(err, "image-registry operator is not becomes available in 100 seconds")
				}
			}()
			err = oc.WithoutNamespace().AsAdmin().Run("patch").Args("configs.imageregistry/cluster", "-p", `{"spec":{"managementState":"Removed"}}`, "--type=merge").Execute()
			o.Expect(err).NotTo(o.HaveOccurred())

			g.By(fmt.Sprintf("%v. Waiting KAS and Image registry reboot after the Internal Image Registry was disabled", currentStep+3))
			e2e.Logf("Checking kube-apiserver operator should be in Progressing in 100 seconds")
			expectedStatus := map[string]string{"Progressing": "True"}
			err = waitCoBecomes(oc, "kube-apiserver", 100, expectedStatus)
			assertWaitPollNoErr(err, "kube-apiserver operator is not start progressing in 100 seconds")
			e2e.Logf("Checking kube-apiserver operator should be Available in 1500 seconds")
			expectedStatus = map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
			err = waitCoBecomes(oc, "kube-apiserver", 1500, expectedStatus)
			assertWaitPollNoErr(err, "kube-apiserver operator is not becomes available in 1500 seconds")
			err = waitCoBecomes(oc, "image-registry", 100, expectedStatus)
			assertWaitPollNoErr(err, "image-registry operator is not becomes available in 100 seconds")

			g.By(fmt.Sprintf("%v. Check if Token and Dockercfg Secrets of SA test-a are removed", currentStep+4))
			secretOutput, err = getResource(oc, asAdmin, withoutNamespace, "secrets", "-n", namespace, "-o", `jsonpath={range .items[*]}{.metadata.name}`)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(secretOutput).Should(o.BeEmpty())
			dockerOutput, err = getResource(oc, asAdmin, withoutNamespace, "sa", "test-a", "-n", namespace, "-o", `jsonpath='{.secrets[*].name}'`)
			o.Expect(err).NotTo(o.HaveOccurred())
			o.Expect(dockerOutput).ShouldNot(o.ContainSubstring("dockercfg"))
			currentStep = currentStep + 5
		}

		g.By(fmt.Sprintf("%v. Create serviceAccount test-b", currentStep))
		err = oc.WithoutNamespace().AsAdmin().Run("create").Args("sa", "test-b", "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("%v. Check if Token and Dockercfg Secrets of SA test-b are created.", currentStep+1))
		secretOutput, err = getResource(oc, asAdmin, withoutNamespace, "secrets", "-n", namespace, "-o", `jsonpath={range .items[*]}{.metadata.name}`)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(secretOutput).Should(o.BeEmpty())
		dockerOutput, err = getResource(oc, asAdmin, withoutNamespace, "sa", "test-b", "-n", namespace, "-o", `jsonpath='{.secrets[*].name}'`)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(dockerOutput).ShouldNot(o.ContainSubstring("dockercfg"))

		g.By(fmt.Sprintf("%v. Create new token and dockercfg secrets from any content for SA test-b", currentStep+2))
		newSecretErr := oc.Run("create").Args("-n", namespace, "secret", "generic", "test-b-dockercfg-ocp68400", "--from-literal=username=myuser", "--from-literal=password=mypassword").NotShowInfo().Execute()
		o.Expect(newSecretErr).NotTo(o.HaveOccurred())
		newSecretErr = oc.Run("create").Args("-n", namespace, "secret", "generic", "test-b-token-ocp68400", "--from-literal=username=myuser", "--from-literal=password=mypassword").NotShowInfo().Execute()
		o.Expect(newSecretErr).NotTo(o.HaveOccurred())

		g.By(fmt.Sprintf("%v. Check if Token and Dockercfg Secrets of SA test-b are not removed", currentStep+3))
		secretOutput = getResourceToBeReady(oc, asAdmin, withoutNamespace, "secrets", "-n", namespace, "-o", "jsonpath='{range .items[*]}{.metadata.name}'")
		o.Expect(string(secretOutput)).To(o.ContainSubstring("test-b-dockercfg-ocp68400"))
		o.Expect(string(secretOutput)).To(o.ContainSubstring("test-b-token-ocp68400"))

		g.By(fmt.Sprintf("%v. Check if Token and Dockercfg Secrets of SA test-b should not have serviceAccount references", currentStep+4))
		secretOutput, err = getResource(oc, asAdmin, withoutNamespace, "secret", "test-b-token-ocp68400", "-n", namespace, "-o", `jsonpath={.metadata.annotations.kubernetes\.io/service-account\.name}`)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(secretOutput).Should(o.BeEmpty())
		secretOutput, err = getResource(oc, asAdmin, withoutNamespace, "secret", "test-b-dockercfg-ocp68400", "-n", namespace, "-o", `jsonpath={.metadata.annotations.kubernetes\.io/service-account\.name}`)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(secretOutput).Should(o.BeEmpty())

		g.By(fmt.Sprintf("%v. Pull image from public registry after disabling internal registry", currentStep+5))
		err = oc.AsAdmin().WithoutNamespace().Run("new-app").Args("registry.access.redhat.com/ubi8/httpd-24", "-n", namespace).Execute()
		o.Expect(err).NotTo(o.HaveOccurred())
		podName := getPodsList(oc.AsAdmin(), namespace)
		assertPodToBeReady(oc, podName[0], namespace)
	})
})
