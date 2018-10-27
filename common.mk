srcs-to-objs = \
	$(patsubst $(1)/%.c,$(2)/%.o,$(filter %.c,$($(3)-srcs))) \
	$(patsubst $(1)/%.s,$(2)/%.o,$(filter %.s,$($(3)-srcs)))

ifeq ($(Q),@)
quiet	= quiet_
endif

cmd = @$(if $($(quiet)cmd_$(1)), \
	echo '$($(quiet)cmd_$(1))' &&) $(cmd_$(1))

echo-cmd = $(if $($(quiet)cmd_$(1)),echo '  $($(quiet)cmd_$(1))' &&)

quiet_cmd_host-prog = HOSTLD	$@
      cmd_host-prog = $(HOSTCC) $(HOSTLDFLAGS) $(HOSTLDFLAGS_$(@F)) $($(@F)-objs) -o $@

quiet_cmd_cc_o_c = CC	$@
      cmd_cc_o_c = $(CC) $(CFLAGS) -I$(dir $(CLOSURE_TMPL)) -c $< -o $@

quiet_cmd_nasm_o_s = NASM	$@
      cmd_nasm_o_s = $(NASM) $(AFLAGS) $(AFLAGS_$(@F)) $< -o $@

quiet_cmd_go = GO	$@
      cmd_go = $(GO) build $(GOFLAGS) -o $@ $^

quiet_cmd_ld = LD	$@
      cmd_ld = $(LD) $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDFLAGS_$(@F)) \
               $(filter-out linker_script,$^) -o $@

quiet_cmd_strip = STRIP	$@
      cmd_strip = $(STRIP) $(STRIPFLAGS) $(STRIPFLAGS_$(@F)) $< -o $@

quiet_cmd_objcopy = OBJCOPY	$@
      cmd_objcopy = $(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@

quiet_cmd_dd = DD	$@
      cmd_dd = $(DD) if=$< of=$@ $(DDFLAGS) $(DDFLAGS_$(@F))

quiet_cmd_nasm_ld = NASM_LD	$@
      cmd_nasm_ld = $(NASM) $(NASMFLAGS) $(NASMFLAGS_$(@F)) $< -o $@

quiet_cmd_cat = CAT	$@
      cmd_cat = $(CAT) $^ > $@
