.PHONY: help list list-all build clean run stop

BENCHMARK_PATH=benchmarks/$(BENCHMARK)
BENCHMARK_JSON=$(BENCHMARK_PATH)/benchmark.json
APY_BENCHMARKS=$(sort $(notdir $(wildcard benchmarks/APY-*-*/benchmark.json)))
ALL_BENCHMARKS=$(sort $(notdir $(wildcard benchmarks/*/benchmark.json)))

help:
	@echo "ApyGuard benchmark commands"
	@echo ""
	@echo "  make list"
	@echo "  make list-all"
	@echo "  make build BENCHMARK=APY-001-26"
	@echo "  make run BENCHMARK=APY-001-26"
	@echo "  make stop BENCHMARK=APY-001-26"
	@echo "  make clean BENCHMARK=APY-001-26"

list:
	@printf "%s\n" $(APY_BENCHMARKS)

list-all:
	@printf "%s\n" $(ALL_BENCHMARKS)

run-all:
	@for b in $(APY_BENCHMARKS); do \
		echo "Running $$b"; \
		$(MAKE) run BENCHMARK=$$b; \
	done

stop-all:
	@for b in $(APY_BENCHMARKS); do \
		echo "Stopping $$b"; \
		$(MAKE) stop BENCHMARK=$$b; \
	done

check-env:
ifndef BENCHMARK
	$(error "no BENCHMARK= value defined, expected something like APY-001-26")
endif

check-valid-benchmark:
	@test -f "$(BENCHMARK_JSON)" || (echo "missing/invalid $(BENCHMARK_JSON) for '$(BENCHMARK)'." && exit 1)

build: check-env check-valid-benchmark
	@$(MAKE) -C $(BENCHMARK_PATH) build

clean: check-env check-valid-benchmark
	@$(MAKE) -C $(BENCHMARK_PATH) clean

run: check-env check-valid-benchmark
	@$(MAKE) -C $(BENCHMARK_PATH) run

stop: check-env check-valid-benchmark
	@$(MAKE) -C $(BENCHMARK_PATH) stop
