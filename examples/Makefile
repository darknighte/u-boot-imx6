ifndef CONFIG_SANDBOX

ifdef FTRACE
# can't build examples with kernel tracing
KBUILD_CFLAGS := $(filter-out -finstrument-functions -DFTRACE, $(KBUILD_CFLAGS))
endif

subdir-y += standalone
subdir-$(CONFIG_API) += api
endif
