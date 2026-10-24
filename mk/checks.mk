.PHONY: check-layout check-docs check-dt check-fast build-manifest
check-layout:
	python3 $(ROOT)/tools/checks/layout.py
check-docs:
	$(MAKE) -C $(ROOT)/docs html BUILDDIR="$(REPORTS_DIR)/docs" SPHINXOPTS="-n -W --keep-going"
check-dt:
	python3 $(ROOT)/tools/checks/devicetree.py --cross-compile "$(CROSS_COMPILE)" --output "$(REPORTS_DIR)/devicetree"
check-fast: check-layout check-docs check-dt
build-manifest:
	python3 $(ROOT)/tools/release/manifest.py --compiler "$(CC)" --idf "$(dir $(IDF_EXPORT))" --output-root "$(BUILD_DIR)" --output "$(IMAGES_DIR)/build-manifest.json"
