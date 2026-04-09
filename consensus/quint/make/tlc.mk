# tlc-controlled: install, build, sync, compile spec, run server.
#
# All runtime targets delegate to scripts/tlc.sh; see that script for
# env var overrides (TLC_PORT, TLC_BUILD_DIR, TLC_JAR, ...).
#
#   make tlc_install                    # clone repo + copy mapper
#   make tlc_sync                       # copy mapper + rebuild jar
#   make tlc_build                      # full install + build
#   make tlc_compile TLA_QUINT_SPEC=main_n4f1b0.qnt
#   make tlc_run                        # start server
#   make tlc_run TLC_PORT=2024          # custom port
#   make tlc_status                     # check if alive
#   make tlc_kill                       # stop server

TLA_QUINT_SPEC ?= main_n4f1b0_tla.qnt
TLC_CONTROLLED_REPO ?= git@github.com:burcuku/tlc-controlled.git
TLC_CONTROLLED_DIR ?= tlc-controlled
TLC_MAPPER_SRC ?= tlc/SimplexActionMapper.java
TLC_MAPPER_DST ?= $(TLC_CONTROLLED_DIR)/src/tlc2/controlled/protocol/SimplexActionMapper.java

.PHONY: tlc_install tlc_sync tlc_build tlc_compile tlc_run tlc_status tlc_kill tlc_clean

# Clone tlc-controlled from GitHub and copy our SimplexActionMapper into it.
tlc_install:
	@if [ -d "$(TLC_CONTROLLED_DIR)" ]; then \
		echo "$(TLC_CONTROLLED_DIR) already exists, updating mapper only"; \
	else \
		echo "Cloning $(TLC_CONTROLLED_REPO) into $(TLC_CONTROLLED_DIR)"; \
		git clone "$(TLC_CONTROLLED_REPO)" "$(TLC_CONTROLLED_DIR)"; \
	fi
	cp "$(TLC_MAPPER_SRC)" "$(TLC_MAPPER_DST)"
	@echo "Installed SimplexActionMapper.java into $(TLC_CONTROLLED_DIR)"

# Copy our SimplexActionMapper into tlc-controlled and rebuild.
tlc_sync:
	cp "$(TLC_MAPPER_SRC)" "$(TLC_MAPPER_DST)"
	cd "$(TLC_CONTROLLED_DIR)" && ant -f customBuild.xml compile && ant -f customBuild.xml dist
	@echo "Synced and rebuilt SimplexActionMapper"

# Build (compile + package) tlc-controlled. Requires ant and a JDK.
tlc_build: tlc_install
	mkdir -p "$(TLC_CONTROLLED_DIR)/test-class"
	cd "$(TLC_CONTROLLED_DIR)" && ant -f customBuild.xml compile && ant -f customBuild.xml dist
	@echo "Built $(TLC_CONTROLLED_DIR)/dist/tla2tools_server.jar"

tlc_compile:
	./scripts/tlc.sh compile $(TLA_QUINT_SPEC)

tlc_run:
	./scripts/tlc.sh run

tlc_status:
	./scripts/tlc.sh status

tlc_kill:
	./scripts/tlc.sh kill

tlc_clean:
	./scripts/tlc.sh clean
