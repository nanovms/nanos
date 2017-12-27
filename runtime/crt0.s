        global _start
        extern init_service
        
_start:
        call init_service
;; can we shut down qemu from here?
        hlt




