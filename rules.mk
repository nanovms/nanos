$(CONTGEN):
	$(MAKE) -C $(ROOT)/contgen

$(CLOSURE_TMPL): $(CONTGEN)
	@ echo "GEN	$@"
	@ mkdir -p $(dir $@)
	$(Q) $(CONTGEN) 10 10 > $@

$(OUT)/%.o: $(ROOT)/%.s
	$(call cmd,nasm_o_s)

$(OUT)/%.o: $(ROOT)/%.c
	$(call cmd,cc_o_c)

$(OUT)/%: %.go
	$(call cmd,go)

%/.vendored:
	@ echo "VENDOR	$(@D)"
	$(Q) $(RM) -rf $(@D)
	$(Q) git clone $(GITFLAGS) $(@D)
	$(Q) touch $@

print-%: ; @ echo $* = $($*)

default-clean:
	$(Q) $(RM) -f $(clean-objs)
	$(Q) [ -d $(OUT) ] && find $(OUT) -type d | sort -r | xargs rm -fd || true

dummy := $(foreach d,$(dir $(clean-objs)), $(shell [ -d $(d) ] || mkdir -p $(d)))
