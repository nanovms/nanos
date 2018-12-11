srcs-to-objs = \
	$(patsubst $(1)/%.c,$(2)/%.o,$(filter %.c,$($(3)-srcs))) \
	$(patsubst $(1)/%.s,$(2)/%.o,$(filter %.s,$($(3)-srcs)))

cmd = $(if $(Q),@ echo "$(msg_$(1))";) $(cmd_$(1))

msg_host-prog     = HOSTLD	$@
cmd_host-prog     = $(HOSTCC) $(HOSTLDFLAGS) $(HOSTLDFLAGS_$(@F)) $($(@F)-objs) $(EXTRA_HOSTLDFLAGS) -o $@

msg_cc_o_c        = CC	$@
cmd_cc_o_c        = $(CC) $(CFLAGS) $(DDFLAGS_$(@F)) -I$(dir $(CLOSURE_TMPL)) -c $< -o $@

msg_nasm_o_s      = NASM	$@
cmd_nasm_o_s      = $(NASM) $(AFLAGS) $(AFLAGS_$(@F)) $< -o $@

msg_go            = GO	$@
cmd_go            = $(GO) build $(GOFLAGS) -o $@ $^

msg_ld            = LD	$@
cmd_ld            = $(LD) $(LDFLAGS) $(EXTRA_LDFLAGS) $(LDFLAGS_$(@F)) \
                        $(filter-out linker_script,$^) -o $@

msg_strip         = STRIP	$@
cmd_strip         = $(STRIP) $(STRIPFLAGS) $(STRIPFLAGS_$(@F)) $< -o $@

msg_objcopy       = OBJCOPY	$@
cmd_objcopy       = $(OBJCOPY) $(OBJCOPYFLAGS) $(OBJCOPYFLAGS_$(@F)) $< $@

msg_objdump       = OBJDUMP	$@.dis
cmd_objdump       = $(OBJDUMP) $(OBJDUMPFLAGS) $(OBJDUMPFLAGS_$(@F)) $< $@ > $@.dis

msg_dd            = DD	$@
cmd_dd            = $(DD) if=$< of=$@ $(DDFLAGS) $(DDFLAGS_$(@F))

msg_nasm_ld       = NASM_LD	$@
cmd_nasm_ld       = $(NASM) $(NASMFLAGS) $(NASMFLAGS_$(@F)) $< -o $@

msg_cat = CAT	$@
cmd_cat = $(CAT) $^ > $@
