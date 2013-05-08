//当我们在命令行里面敲入 ./notepad.exe的时候，首先linux内核调用execve系统调用，
//最终走到我们兼容模块的load_pe_bianry

/*
 * load_pe_binary
 */
static int load_pe_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	IMAGE_DOS_HEADER	*dos_hdr;
	struct win32_section	*ws = NULL;
	struct win32_image_section	*wis;
	unsigned long error;
	unsigned long pe_addr = 0;
	int retval = 0;
	unsigned long pe_entry, ntdll_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc = 0;
	unsigned long ntdll_entry;
	struct mm_struct    *mm;
	int executable_stack = EXSTACK_DEFAULT;
	unsigned long def_flags = 0;
	unsigned long stack_top;
	unsigned long ret_addr = 0xdeadbeef;
	unsigned long start_address;
	unsigned long pe_brk = 0;
#ifdef NTDLL_SO
	unsigned long	interp_load_addr;
	unsigned long	interp_entry;
#endif
	int		maped = 0;
	struct eprocess	*process;
	struct ethread	*thread;
	PRTL_USER_PROCESS_PARAMETERS	ppb;
	PKAPC	thread_apc;
	OBJECT_ATTRIBUTES	ObjectAttributes;
	INITIAL_TEB	init_teb;

	BOOLEAN is_win32=FALSE;
    struct startup_info *info=NULL;
    struct eprocess	*parent_eprocess=NULL;
    struct ethread	*parent_ethread=NULL;
	struct w32process* child_w32process =NULL;
	struct w32process* parent_w32process =NULL;

	/* check the DOS header */
	retval = -ENOEXEC;
	dos_hdr = (IMAGE_DOS_HEADER *)bprm->buf;
	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE || dos_hdr->e_lfanew <= 0)
		goto out;

	ktrace("bprm=%p\n", bprm);
	retval = -ENOMEM;
	ws = (struct win32_section *)kmalloc(sizeof(struct win32_section), GFP_KERNEL);
	if (!ws)
		goto out;
	memset(ws, 0, sizeof(*ws));

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

    if(current->parent->ethread)//父进程如果是win32程序
    {
		is_win32 = TRUE;
		parent_ethread = current->parent->ethread;
		parent_eprocess = parent_ethread->threads_process;
    }

	/* Flush all traces of the currently running executable */
	retval = flush_old_exec(bprm);
	if (retval) {
		kfree(ws);
		goto out;
	}

	/* OK, This is the point of no return */
	mm = current->mm;
	current->flags &= ~PF_FORKNOEXEC;
	mm->def_flags = def_flags;

	current->signal->rlim[RLIMIT_STACK].rlim_cur = WIN32_STACK_LIMIT;
	current->signal->rlim[RLIMIT_STACK].rlim_max = WIN32_STACK_LIMIT;
	current->personality |= ADDR_COMPAT_LAYOUT;
	setup_new_exec(bprm);

	mm->free_area_cache = mm->mmap_base = WIN32_UNMAPPED_BASE;
	mm->cached_hole_size = 0;
	stack_top = WIN32_STACK_LIMIT + WIN32_LOWEST_ADDR;
	retval = setup_arg_pages(bprm, stack_top, executable_stack);
	if (retval < 0)
		goto out_free_file;

	/* map PE image */
	ws->ws_file = bprm->file;
	image_section_setup(ws);
	ws->ws_mmap(current, ws, &pe_addr, 0, 0, 0);//image_section_map 映射PE文件
	maped = 1;

	down_write(&mm->mmap_sem);
	/* reserve first 0x100000 */
	do_mmap_pgoff(NULL, 0, WIN32_LOWEST_ADDR, PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	/* reserve first 0x7fff0000 - 0x80000000 */
	do_mmap_pgoff(NULL, WIN32_TASK_SIZE - 0x10000, 0x10000,
			PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	/* reserve first 0x81000000 - 0xc0000000
	 * 0x80000000 - 0x81000000 used for wine SYSTEM_HEAP */
	do_mmap_pgoff(NULL, WIN32_TASK_SIZE + WIN32_SYSTEM_HEAP_SIZE,
			TASK_SIZE - WIN32_TASK_SIZE - WIN32_SYSTEM_HEAP_SIZE,
			PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0);
	up_write(&mm->mmap_sem);

	/* adjust stack in 0x100000 - 0x300000
	 * 0x100000 - 0x101000 is not access */
	adjust_stack(bprm->p);

	/* Now we do a little grungy work by mmaping the PE image into
	   the correct location in memory.  At this point, we assume that
	   the image should be loaded at fixed address, not at a variable
	   address. */
	for (wis = ws->ws_sections; wis < ws->ws_sections + ws->ws_nsecs; wis++) {
		unsigned long k;

		if (wis->wis_character & IMAGE_SCN_TYPE_NOLOAD)
			continue;

		k = ws->ws_realbase + wis->wis_rva;

		/*
		 * Check to see if the section's size will overflow the
		 * allowed task size. Note that p_filesz must always be
		 * <= p_memsz so it is only necessary to check p_memsz.
		 */
		if (k > TASK_SIZE || TASK_SIZE - wis->wis_size < k) /* Avoid overflows.  */
			goto out_free_file;

		if (wis->wis_character & IMAGE_SCN_MEM_EXECUTE) {
			start_code = k;
			end_code = k + wis->wis_rawsize;
		}
		else {
			if (!start_data)
				start_data = k;
			end_data = k + wis->wis_rawsize;
		}

		k += wis->wis_size;
		if (pe_brk < k)	/* pe_brk used set mm->brk */
			pe_brk = k;

		/* TODO: start_data and end_data, diff to ELF */
	}

	mm->brk = pe_brk;

	/* extra page, used for interpreter ld-linux.so */
	down_write(&mm->mmap_sem);
	if ((extra_page = do_brk(pe_brk, PAGE_SIZE)) != pe_brk) {
		up_write(&mm->mmap_sem);
		goto out_free_file;
	}
	up_write(&mm->mmap_sem);
	mm->brk = pe_brk + PAGE_SIZE;

	ws->ws_entrypoint += ws->ws_realbase;

#ifdef NTDLL_SO
	/* search ntdll.dll.so in $PATH, default is /usr/local/lib/wine/ntdll.dll.so */
	if (!*ntdll_name)
		search_ntdll();

	/* map ntdll.dll.so */
	map_system_dll(current, ntdll_name, &ntdll_load_addr, &interp_load_addr);//映射ntdll.dll.so

	pe_entry = get_pe_entry();
	ntdll_entry = get_ntdll_entry();
	interp_entry = get_interp_entry();
#endif
	reloc_func_desc = 0;

	set_binfmt(&pe_format);

	INIT_OBJECT_ATTR(&ObjectAttributes, NULL, 0, NULL, NULL);

	/* Create EPROCESS */
	retval = create_object(KernelMode,
			process_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct eprocess),
			0,
			0,
			(PVOID *)&process);
	if (retval != STATUS_SUCCESS) {
		goto out_free_file;
	}

	/* init eprocess */
	eprocess_init(NULL, FALSE, process);
	process->unique_processid = create_cid_handle(process, process_object_type);
	if (!process->unique_processid)
		goto out_free_eproc;

	insert_reserved_area(process, WIN32_LOWEST_ADDR,
			WIN32_LOWEST_ADDR + WIN32_STACK_LIMIT, _PAGE_READWRITE);

	/* initialize EProcess and KProcess */
	process->section_base_address = (void *)ws->ws_realbase;
	insert_mapped_area(process, ws->ws_realbase, ws->ws_realbase + ws->ws_pagelen, _PAGE_READONLY, NULL);

	/* Create PEB */
	if ((retval = create_peb(process)))
		goto out_free_process_cid;

	/* Create PPB */
	if(is_win32 == FALSE)
	{
		create_ppb(&ppb, process, bprm, bprm->filename, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		((PEB *)process->peb)->ProcessParameters = ppb;
	}
#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
	retval = arch_setup_additional_pages(bprm, executable_stack);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		goto out_free_process_cid;
	}
#endif /* ARCH_HAS_SETUP_ADDITIONAL_PAGES */

	install_exec_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
#ifdef NTDLL_SO
	/* copy argv, env, and auxvec to stack, all for interpreter */
	create_elf_tables(bprm, ntdll_load_addr, ntdll_phoff, ntdll_phnum, get_start_thunk());
#endif

	/* Set the Esp */
#ifdef CONFIG_STACK_GROWSUP
	/* FIXME */
#else
	/* setup user stack */
	/* -------------    -----------
	   param            PEB_BASE
	   -------------    -----------
	   start_address    entry point
	   -------------    -----------
	   ret_addr         0xdeadbeef
	   -------------    -----------
	   */
	bprm->p = bprm->p			/* stack_top */
		- sizeof(ret_addr)			/* return address, BAD address */
		- sizeof(start_address)		/* image entry point */
		- sizeof(unsigned long);	/* paramters for entry point */
	start_address = ws->ws_entrypoint;
	*(unsigned long *)bprm->p = ret_addr;
	*(unsigned long *)(bprm->p + sizeof(ret_addr)) = start_address;
	*(unsigned long *)(bprm->p + sizeof(ret_addr) + sizeof(start_address)) = PEB_BASE;
#endif

	mm->end_code = end_code;
	mm->start_code = start_code;
	mm->start_data = start_data;
	mm->end_data = end_data;
	mm->start_stack = bprm->p;

	if (current->personality & MMAP_PAGE_ZERO) {
		/* Why this, you ask???  Well SVr4 maps page 0 as read-only,
		   and some applications "depend" upon this behavior.
		   Since we do not have the power to recompile these, we
		   emulate the SVr4 behavior. Sigh. */
		down_write(&mm->mmap_sem);
		error = do_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&mm->mmap_sem);
	}

	/* allocate a Win32 thread object */
	retval = create_object(KernelMode,
			thread_object_type,
			&ObjectAttributes,
			KernelMode,
			NULL,
			sizeof(struct ethread),
			0,
			0,
			(PVOID *)&thread);
	if (retval) {
		goto out_free_process_cid;
	}

	thread->cid.unique_thread = create_cid_handle(thread, thread_object_type);
	thread->cid.unique_process = process->unique_processid;
	if (!thread->cid.unique_thread)
		goto out_free_ethread;

	/* set the teb */
	init_teb.StackBase = (PVOID)(bprm->p);
	init_teb.StackLimit = (PVOID)WIN32_LOWEST_ADDR + PAGE_SIZE;
	thread->tcb.teb = create_teb(process, (PCLIENT_ID)&thread->cid, &init_teb);
	if (IS_ERR(thread->tcb.teb)) {
		retval = PTR_ERR(thread->tcb.teb);
		goto out_free_thread_cid;
	}

	/* Init KThread */
	ethread_init(thread, process, current);

	if (is_win32 == TRUE) //parent is a windows process
	{
		up(&parent_ethread->exec_semaphore);
		down(&thread->exec_semaphore);  //wait for the parent

		child_w32process = process->win32process;
		parent_w32process = parent_eprocess->win32process;
		info = child_w32process->startup_info;

		//now parent has finished its work
		if(thread->inherit_all)
		{
			create_handle_table(parent_eprocess, TRUE, process);
			child_w32process = create_w32process(parent_w32process, TRUE, process);
		}
	}


	deref_object(process);
	deref_object(thread);

	set_teb_selector(current, (long)thread->tcb.teb);

	thread->start_address = (void *)pe_entry;	/* FIXME */

	/* init apc, to call LdrInitializeThunk */
	thread_apc = kmalloc(sizeof(KAPC), GFP_KERNEL);
	if (!thread_apc) {
		retval = -ENOMEM;
		goto out_free_thread_cid;
	}
	apc_init(thread_apc,
			&thread->tcb,
			OriginalApcEnvironment,
			thread_special_apc,
			NULL,
			(PKNORMAL_ROUTINE)ntdll_entry,
			UserMode,
			(void *)(bprm->p + 12));
	insert_queue_apc(thread_apc, (void *)interp_entry, (void *)extra_page, NULL,IO_NO_INCREMENT);
	set_tsk_thread_flag(current, TIF_APC);

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  In addition, it may also specify (eg, PowerPC64 ELF)
	 * that the e_entry field is the address of the function descriptor
	 * for the startup routine, rather than the address of the startup
	 * routine itself.  This macro performs whatever initialization to
	 * the regs structure is required as well as any relocations to the
	 * function descriptor entries when executing dynamically links apps.
	 */
	ELF_PLAT_INIT(regs, reloc_func_desc);
#endif

	start_thread(regs, pe_entry, bprm->p);
	if (unlikely(current->ptrace & PT_PTRACED)) {
		if (current->ptrace & PT_TRACE_EXEC)
			ptrace_notify ((PTRACE_EVENT_EXEC << 8) | SIGTRAP);
		else
			send_sig(SIGTRAP, current, 0);
	}

	/* save current trap frame */
	thread->tcb.trap_frame = (struct ktrap_frame *)regs;
	retval = 0;

	try_module_get(THIS_MODULE); 
	/* return from w32syscall_exit, not syscall_exit */
	((unsigned long *)regs)[-1] = (unsigned long)w32syscall_exit;//设置linux系统调用从w32syscall_exit返回
	regs->fs = TEB_SELECTOR;

	if (ws) {
		if (ws->ws_sections)
			kfree(ws->ws_sections);
		kfree(ws);
	}
out:
	return retval;

	/* error cleanup */
out_free_thread_cid:
	delete_cid_handle(thread->cid.unique_thread, thread_object_type);
out_free_ethread:
	deref_object(thread);
out_free_process_cid:
	delete_cid_handle(process->unique_processid, process_object_type);
out_free_eproc:
	deref_object(process);
out_free_file:
	/* free win32_section, if not mapped */
	if (!maped && ws) {
		if (ws->ws_sections)
			kfree(ws->ws_sections);
		kfree(ws);
		ws=NULL;
	}
	send_sig(SIGKILL, current, 0);
	goto out;
} /* end load_pe_binary */

//execve系统调用从w32syscall_exit返回
//w32entry.S (module_2.6.34\ke):	jmp w32syscall_exit

ENTRY(w32syscall_exit)
	LOCKDEP_SYS_EXIT
	DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we dont miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
	TRACE_IRQS_OFF

	#check whether syscall number can run apc.
	movl $0,%eax
	call no_apc_syscall_number
	testl $1,%eax	
	jnz w32restore_all	

	movl TI_flags(%ebp), %ecx
	testl $_TIF_ALLWORK_MASK, %ecx	# current->work
	jne w32syscall_exit_work

w32restore_all:
	movl PT_EFLAGS(%esp), %eax	# mix EFLAGS, SS and CS
	# Warning: PT_OLDSS(%esp) contains the wrong/random values if we
	# are returning to the kernel.
	# See comments in process.c:copy_thread() for details.
	movb PT_OLDSS(%esp), %ah
	movb PT_CS(%esp), %al
	andl $(X86_EFLAGS_VM | (SEGMENT_TI_MASK << 8) | SEGMENT_RPL_MASK), %eax
	cmpl $((SEGMENT_LDT << 8) | USER_RPL), %eax
	CFI_REMEMBER_STATE
	je w32ldt_ss			# returning to user-space with LDT SS
	
w32restore_nocheck:
	TRACE_IRQS_IRET
w32restore_nocheck_notrace:
	RESTORE_REGS 4			# skip orig_eax/error_code
	CFI_ADJUST_CFA_OFFSET -4
irq_return:
	INTERRUPT_RETURN  #iret

//w32syscall_exit_work
	# perform syscall exit tracing
	ALIGN
w32syscall_exit_work:
	testl $_TIF_WORK_SYSCALL_EXIT, %ecx
	jz w32work_pending
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS(CLBR_ANY)	# could let syscall_trace_leave() call
					# schedule() instead
	movl %esp, %eax
	call syscall_trace_leave
	jmp w32resume_userspace
END(w32syscall_exit_work)

//w32work_pending

					w32work_pending:
						testb $_TIF_NEED_RESCHED, %cl
						jz w32work_notifysig
						
					w32work_resched:
						call schedule
						LOCKDEP_SYS_EXIT
						DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we dont miss an interrupt
					# setting need_resched or sigpending
					# between sampling and the iret
						TRACE_IRQS_OFF
						movl TI_flags(%ebp), %ecx
						andl $_TIF_WORK_MASK, %ecx	# is there any work to be done other
					# than syscall tracing?
						jz w32restore_all
						testb $_TIF_NEED_RESCHED, %cl
						jnz w32work_resched
//w32work_notifysig
					w32work_notifysig:			# deal with pending signals and
					# notify-resume requests
#ifdef CONFIG_VM86
						testl $X86_EFLAGS_VM, PT_EFLAGS(%esp)
						movl %esp, %eax
						je w32apc			# returning to kernel-space or
					# vm86-space
						ALIGN
					w32work_notifysig_v86:
						pushl %ecx			# save ti_flags for do_notify_resume
						CFI_ADJUST_CFA_OFFSET 4
						call save_v86_state 	# %eax contains pt_regs pointer
						popl %ecx
						CFI_ADJUST_CFA_OFFSET -4
						movl %eax, %esp
#else
						movl %esp, %eax
#endif

//w32apc					
					w32apc:
						xorl %edx, %edx
						testw $_TIF_APC, %cx
						jz w32signal				
					
						call do_apc 					# for Windows Apc	 
						movl TI_flags(%ebp), %ecx
						testw $(_TIF_WORK_MASK & ~_TIF_APC), %cx
						jz w32resume_userspace_sig
						xorl %edx, %edx
						movl %esp, %eax
//w32signal				
					w32signal:
						call do_notify_resume
						jmp w32resume_userspace_sig
					
					END(w32work_pending)

					

//最后设置的一个用户apc，在execve系统调用返回的时候会调用do_apc
/* do_apc */
//__attribute__((regparm(3)))
void do_apc(struct pt_regs *regs, sigset_t *oldset,
		      __u32 thread_info_flags)
{
	bool flag = 0;
	struct kthread *kthread;
	struct ethread *thread;
	ktrace("Do Apc\n");

#if 0	
	down(&kernel_lock);
#endif
	syscall_lock_down();

	kthread = (struct kthread *)get_current_ethread();
	flag = kthread->last_syscall_number == 0 || kthread->last_syscall_number == 21 || kthread->last_syscall_number == 222 ||  \
				kthread->last_syscall_number == 232 || kthread->last_syscall_number == 233;
	if(flag == 0)
	{
		printk("kthread:%p,last_syscall_number:%d\n",kthread,kthread->last_syscall_number);
	}

	/* Get the Current Thread */
	if (!(thread = get_current_ethread())) {
		clear_tsk_thread_flag(thread->et_task, TIF_APC);
		return;
	}
	deliver_apc(UserMode, 0, regs); /* first parament is kernelMode or UserMode or 0 for both*/

#if 0
	up(&kernel_lock);
#endif
	syscall_lock_up();

}/* end do_apc */

//执行用户态的apc

VOID 
STDCALL
deliver_apc(KPROCESSOR_MODE DeliveryMode,
		PVOID Reserved,
		struct pt_regs * TrapFrame)
{
	struct ethread *thread;
	struct kthread *kthread;
	struct list_head * apc_listentry; 
	struct kapc *apc = NULL;
	kernel_routine_t kernel_routine;
	void * normal_context;
	normal_routine_t normal_routine;
	void *system_argument1;
	void *system_argument2;
	void *system_argument3;
	int kernelmode_count = 0;

	ktrace("(DeliverMode 0x%x, Reserved 0x%p, TrapFrame 0x%p)\n", 
			DeliveryMode, Reserved, TrapFrame);

	if (!(thread = get_current_ethread())) {	
		clear_tsk_thread_flag(current, TIF_APC);
		return;
	}
	//printk("DeliverMode 0x%x, pid:%d\n",DeliveryMode,current->pid);
	kthread = (struct kthread *)thread;

	/* 
	 * Do the Kernel APCs first 
	 * only by wait.c's block_thread
	 * need to think carefully.
	 */
	while (DeliveryMode == KernelMode) 
	{
.....
	}

	if(DeliveryMode == UserMode)
	{
		if(thread->tcb.apc_state.uapc_inprogress) 
		{
			thread->tcb.apc_state.uapc_pending = 0;
			clear_tsk_thread_flag(thread->et_task,TIF_APC);
			return;
		}

#if defined(APC_USE_SPIN_LOCK_IRP)
		/* Disable interrupt and lock shared resource */
		spin_lock_irq(&kthread->apc_queue_lock);
#else
		spin_lock_bh(&kthread->apc_queue_lock);
#endif


		/* Now we do the User APCs */
		if ((!list_empty(&thread->tcb.apc_state.apc_list_head[UserMode])) &&
				(thread->tcb.apc_state.uapc_pending)) 
		{

			/* Get the APC Object */
			apc_listentry = thread->tcb.apc_state.apc_list_head[UserMode].next;
			apc = list_entry(apc_listentry, struct kapc, apc_list_entry);

			/* Save Parameters so that it's safe to free the Object in Kernel Routine*/
			normal_routine = apc->normal_routine;
			kernel_routine = apc->kernel_routine;
			normal_context = apc->normal_context;
			system_argument1 = apc->system_argument1;
			system_argument2 = apc->system_argument2; 
			system_argument3 = apc->system_argument3;

			/* Remove the APC from Queue, call the APC */
			list_del_init(apc_listentry);
			(thread->tcb.apc_state.apc_num[UserMode])--;
			apc->inserted = 0;

#if defined(APC_USE_SPIN_LOCK_IRP)
			/* Enable interrupt and unlock shared resource */
			spin_unlock_irq(&kthread->apc_queue_lock);
#else
			spin_unlock_bh(&kthread->apc_queue_lock);
#endif

			kernel_routine(apc,//thread_special_apc
					&normal_routine,
					&normal_context,
					&system_argument1,
					&system_argument2,
					&system_argument3);

			if (!normal_routine) {	//LdrInitializeThunk
				test_alert_thread(UserMode);   /* Unimplemented */
			} else {
			
				thread->tcb.apc_state.uapc_inprogress = TRUE;

				/* 
				 * copy argument,
	 			 * because in other process address space,kernel can not copy argument.
				 */
				if(apc->async_copy_routine)
				{
					apc->async_copy_routine(apc);
				}
				/* Set up the Trap Frame and prepare for Execution in NTDLL.DLL */
				init_user_apc(Reserved, 
						TrapFrame,
						normal_routine,//LdrInitializeThunk
						normal_context,
						system_argument1,
						system_argument2,
						system_argument3); 
			}
		} 
		else
		{
			/* It's not pending anymore */
			thread->tcb.apc_state.uapc_pending = 0;

#if defined(APC_USE_SPIN_LOCK_IRP)
			/* Enable interrupt and unlock shared resource */
			spin_unlock_irq(&kthread->apc_queue_lock);
#else
			spin_unlock_bh(&kthread->apc_queue_lock);
#endif

			/* Clear thread_info's flag */
			clear_tsk_thread_flag(thread->et_task,TIF_APC);
		}			
	}
	return;
} /* end deliver_apc */

VOID
STDCALL
init_user_apc(IN PVOID Reserved,
		IN PKTRAP_FRAME TrapFrame,
		IN PKNORMAL_ROUTINE NormalRoutine,
		IN PVOID NormalContext,
		IN PVOID SystemArgument1,
		IN PVOID SystemArgument2,  
		IN PVOID SystemArgument3) 
{
	PContext context;
	PULONG esp;

	ktrace("ESP 0x%lx\n", TrapFrame->sp);
	/*
	 * Save the thread's current context (in other words the registers
	 * that will be restored when it returns to user mode) so the
	 * APC dispatcher can restore them later
	 */
	context = (PContext)(((PUCHAR)TrapFrame->sp) - sizeof(*context));
	memcpy(context, TrapFrame, sizeof(*context));
	
	/*	  by   2013-05-08 load_pe_binary对apc的设置
	apc_init(thread_apc,
			&thread->tcb,
			OriginalApcEnvironment,
			thread_special_apc,
			NULL,
			(PKNORMAL_ROUTINE)ntdll_entry,//LdrInitializeThunk
			UserMode,
			(void *)(bprm->p + 12));
	insert_queue_apc(thread_apc, (void *)interp_entry, (void *)extra_page, NULL,IO_NO_INCREMENT);
	set_tsk_thread_flag(current, TIF_APC);
	
	*/

	/*
	 * Setup the trap frame so the thread will start executing at the
	 * APC Dispatcher when it returns to user-mode
	 * 7 is arguments' number.
	 */
	esp = (PULONG)(((PUCHAR)TrapFrame->sp) - (sizeof(CONTEXT) + (7 * sizeof(ULONG))));
	esp[0] = 0xdeadbeef;
	esp[1] = (ULONG)NormalRoutine;//LdrInitializeThunk
	esp[2] = (ULONG)NormalContext;//(void *)(bprm->p + 12)
	esp[3] = (ULONG)SystemArgument1;//interp_entry
	esp[4] = (ULONG)SystemArgument2;//extra_page
	esp[5] = (ULONG)SystemArgument3;//NULL
	esp[6] = (ULONG)context;//用户程序的上下文
	TrapFrame->ip = get_apc_dispatcher();//KiUserApcDispatcher
	TrapFrame->sp = (ULONG)esp;
} /* end init_user_apc */


//回到用户空间执行的第一个函数是 KiUserApcDispatcher
//void __attribute__((stdcall, no_instrument_function))
KiUserApcDispatcher(P_WINDOWS_APC_ROUTINE ApcRoutine, void *ApcContext,
        void *SystemArgument1, unsigned long SystemArgument2,void *SystemArgument3, void *Context)
{
	PIO_APC_ROUTINE second_apc = NULL;
	async_data_t *async_data; 

    /*need change SystemArgument2's effect. old code is if(SystemArgument).*/
	if(ApcRoutine == LdrInitializeThunk)
	{
        extra_page = SystemArgument2;
        StartInterp(ApcRoutine, ApcContext, SystemArgument1, SystemArgument2, Context);
		ApcRoutine(ApcContext, SystemArgument1, SystemArgument3,&second_apc);//LdrInitializeThunk
    }
	else if(ApcRoutine == kernel_to_user_apc)
	{
		kernel_to_user_apc(ApcContext,SystemArgument1,SystemArgument3);
	}
	else
	{
		async_data = (async_data_t *)SystemArgument3;

		if(async_data != NULL && async_data->self == async_data)
		{
			NTSTATUS status;
			IO_STATUS_BLOCK* iosb;
			int size;

			status = ApcRoutine(ApcContext, SystemArgument1, async_data->status,&second_apc);	

			if(SystemArgument1)
				iosb = SystemArgument1;

			SERVER_START_REQ(async_set_result)
			{
				req->handle = async_data->handle;
				req->event  = async_data->event;
				req->cvalue = async_data->cvalue;
				req->status = status;
				req->async_handle = async_data->async_handle;
				if(iosb)
					req->total  = iosb->Information;

				req->arg1   = async_data->arg;
				req->arg2   = async_data->iosb;
				wine_server_call(req);
			}
			SERVER_END_REQ;

			if(async_data->self)
			{
				/* end first apc,free memory. */
				void *ptr = async_data->self;
				size = 0;//sizeof(async_data_t);

				printf("KiUserApcDispatcher,before NtFreeVirtualMemory.\n");
				status = NtFreeVirtualMemory(NtCurrentProcess(), &ptr, &size, MEM_RELEASE);
			}
		}
		else
		{
			ApcRoutine(ApcContext, SystemArgument1, SystemArgument3,&second_apc);
		}

		if(second_apc)
		{
			second_apc(ApcContext,SystemArgument1,0);
		}
	}/*end else*/

    /* switch back to the interrupted context */
    NtContinue((PCONTEXT)Context, 1);
}


//1.首先调用StartInterp

__attribute__ ((no_instrument_function)) void StartInterp();

    /*
     * StartInterp
     *
     * The linux interpreter here is used to link .so such as libwine.so for built-in dlls.
     * ALl the dlls will be linked by ntdll.dll.so
     */
__asm__ (
        ".globl StartInterp\n"
        "StartInterp:\n\t"
        "pusha\n\t"
        "mov 0x28(%esp), %ecx\n\t"	/* stack top used for linux arg */
        "sub %esp, %ecx\n\t"		/* stack size need backup */
        "mov %esp, %esi\n\t"
        "mov 0x30(%esp), %edi\n\t"
        "mov %ecx, (%edi)\n\t"		/* backup the size */
        "add $0x4, %edi\n\t"
        "shr $2, %ecx\n\t"
        "rep movsl\n\t"
        "mov 0x28(%esp), %ecx\n\t"
        "mov 0x2c(%esp), %esi\n\t"	/* Iosb, here in interpreter */
        "mov %ecx, %esp\n\t"
        "jmp *%esi\n"				/* _start in interpreter */
        /* finally jmp to AT_ENTRY */

        ".globl StartThunk\n"		/* set StartThunk to AT_ENTRY in kernel */
        "StartThunk:\n\t"
        "xorl %ebp, %ebp\n\t"		/* ABI need */
        "movl (%esp), %esi\n\t"		/* Pop the argument count.  */
        "leal 0x4(%esp), %ecx\n\t"		/* argv starts just at the current stack top.*/
        "movl %esp, %ebp\n\t"
        /* Before pushing the arguments align the stack to a 16-byte
           (SSE needs 16-byte alignment) boundary to avoid penalties from
           misaligned accesses. */
        "andl $0xfffffff0, %esp\n\t"
        "pushl %eax\n\t"	  /* push garbage */
        "pushl %eax\n\t"	  /* push garbage */
        "pushl %eax\n\t"	  /* push garbage */
        "pushl %ebp\n\t"
        "pushl %edx\n\t"      /* Push address of the shared library termination function. */
        "pushl $0x0\n\t"      /* __libc_csu_init */
        "pushl %ecx\n\t"      /* Push second argument: argv.  */
        "pushl %esi\n\t"      /* Push first argument: argc.  */
        "call PrepareThunk\n\t"
        "movl (%esp), %esp\n\t"		/* restore %esp */
        "movl (%eax), %ecx\n\t"		/* stack size backuped */
        "leal 0x4(%eax), %esi\n\t"	/* stack data backuped in %esi */
        "subl %ecx, %esp\n\t"		/* restore %esp */
        "movl %esp, %edi\n\t"
        "shrl $0x2, %ecx\n\t"
        "rep movsl\n\t"				/* restore stack */
        "popa\n\t"
        "ret\n"						/* return from StartInterp */
    );

/*    by   2013-05-08
	StartInterp()的汇编代码有什么作用？

帖子由 古月今人 于 2010-04-16 1041
从load_pe_binary返回用户空间之时，首先是要运行APC，这个APC是在 load_pe_binary中挂入的。
这样，在返回用户空间的时候，首先会调用KiUserApcDispatcher，每个APC都会通过此函数来调用。
这里需要特别关注的是这个函数的参数，这些参数都在load_pe_binary中设定的。
其中，ApcRoutine设定为ntdll中的 LdrInitializeThunk；ApcContext为linux进程堆栈指针，
不包括为PE以及APC附加上去的堆栈；Iosb为解释器 libld-linux.so.2的入口地址；Reserved为一个空闲页面内存的首地址，
此空闲内存用来临时保存为PE和APC附加上去的堆栈内容；Context为NULL。有了这个背景，可以看StartInterp的代码了。

代码 全选
            ".globl StartInterp\n"
            "StartInterp:\n\t"
            "pusha\n\t"                 // 用来把8个通用寄存器压入堆栈，这里相当于保留了现场
            "mov 0x28(%esp), %ecx\n\t"  // 不包括为PE以及APC附加上去的堆栈
            "sub %esp, %ecx\n\t"        // esp是当前堆栈指针，相减后，ecx就是需要备份的字节数
            "mov %esp, %esi\n\t"        // esi设为当前堆栈指针
            "mov 0x30(%esp), %edi\n\t"  // edi设为Reserved，也就是空闲页面地址
            "mov %ecx, (%edi)\n\t"      // 先把备份字节数写入空闲页面中
            "add $0x4, %edi\n\t"        // 递增edi指针
            "shr $2, %ecx\n\t"          // ecx除4，转换为long型数目
            "rep movsl\n\t"             // 将esp开始的ecx个long型备份到空闲页面中
            "mov 0x28(%esp), %ecx\n\t"
            "mov 0x2c(%esp), %esi\n\t"   // esi设为解释器/lib/ld-linux.so.2的入口
            "mov %ecx, %esp\n\t"         // 将堆栈指针设置为不包括PE和APC堆栈的指针
            "jmp *%esi\n"                // 跳转到解释器


之后就进入了解释器lib ld-linux.so.2，那么解释器完成连接ntdll的工作后，会运行到哪里去呢？
答案是StartThunk，在解释器中，会去搜索AT_ENTRY项值，它的跳转目标地址就是AT_ENTRY，
这个值在load_pe_binary中设置为StartThunk。如果是elf文件，那么在load_elf_binary中，
这个值为设置为elf可执行程序的_start，从这里可以调用到程序中的main函数。

代码 全选
            ".globl StartThunk\n"       /* set StartThunk to AT_ENTRY in kernel 
            "StartThunk:\n\t"
            "xorl %ebp, %ebp\n\t"       /* ABI need 
            "movl (%esp), %esi\n\t"     /* Pop the argument count.  
            "leal 0x4(%esp), %ecx\n\t"      /* argv starts just at the current stack top.
            "movl %esp, %ebp\n\t"
            /* Before pushing the arguments align the stack to a 16-byte
               (SSE needs 16-byte alignment) boundary to avoid penalties from
               misaligned accesses. 
            "andl $0xfffffff0, %esp\n\t"
            "pushl %eax\n\t"      /* push garbage 
            "pushl %eax\n\t"      /* push garbage 
            "pushl %eax\n\t"      /* push garbage 
            "pushl %ebp\n\t"     // 压入进入此函数时的堆栈指针，下面4个push是压入参数
            "pushl %edx\n\t"      /* Push address of the shared library termination function. 
            "pushl $0x0\n\t"      /* __libc_csu_init 
            "pushl %ecx\n\t"      /* Push second argument: argv.  
            "pushl %esi\n\t"      /* Push first argument: argc.  
            "call PrepareThunk\n\t"
            "movl (%esp), %esp\n\t"     // 恢复进入此函数时的堆栈指针
            "movl (%eax), %ecx\n\t"     // eax为PrepareThunk的返回值，是空闲页面的地址，其中前面4个字节为备份的字节数
            "leal 0x4(%eax), %esi\n\t"    // esi指向备份的堆栈内容
            "subl %ecx, %esp\n\t"       // 恢复esp指针到包含PE和APC堆栈的位置
            "movl %esp, %edi\n\t"
            "shrl $0x2, %ecx\n\t"
            "rep movsl\n\t"             // 恢复堆栈
            "popa\n\t"                 // 恢复各个通用寄存器
            "ret\n"                     /* return from StartInterp 
       );


这个函数主要是参考了libc中的_start函数，主要目的是调用PrepareThunk，为调用真正的APC函数 LdrInitializeThunk做好准备。
之后，就需要恢复为PE和APC准备的堆栈，否则，将无法从APC调用中返回，更无法进入PE文件的入口。由于popa恢复了在StartInterp
时pusha压入的环境，所以最后一条ret，将返回到KiUserApcDispatcher，之后就进入了LdrInitializeThunk，进行PE文件的链接。
*/

//__attribute__((stdcall))
int PrepareThunk(
            int argc,
            char **argv,
            void (*init) (void),
            void (*rtld_fini)(void))
{
    char	**evp, **p;
    char 	*wine_path, *bin_dir;
    char	wine[] = "/wine";

    LOG(LOG_FILE, 0, 0, "PrepareThunk(), init=%p\n", init);
    if (__builtin_expect (rtld_fini != NULL, 1))
        __cxa_atexit ((void (*) (void *)) rtld_fini, NULL, NULL);

    p = evp = argv + argc + 1;

    while (*p++) ;
    auxvec = (ElfW(auxv_t) *)p;
    auxvec_len = (unsigned long)argv[0] - (unsigned long)p;

    bin_dir = get_wine_bindir();
    wine_path = malloc(strlen(bin_dir) + sizeof(wine));
    strcpy(wine_path, bin_dir);
    strcat(wine_path, wine);
    free(bin_dir);

    wine_init_argv0_path(wine_path);
    build_dll_path();
    __wine_main_argc = argc;
    __wine_main_argv = argv;
    __wine_main_environ = evp;
    free(wine_path);

    init_for_load();

    /* Call the initializer of the program, if any.  */
    if (init)//这个init一般为0
	{
        (*init)();
	}

    /* .init in ntdll.dll.so */ //
    _init();  //__wine_spec_pe_header[] __wine_spec_init_ctor ->__wine_spec_init-> __wine_dll_register() is called here for ntdll.dll
    NtCurrentTeb()->Peb->ProcessParameters->Environment = NULL;
    return extra_page;
}

//2. 回到 KiUserApcDispatcher 执行 LdrInitializeThunk

void WINAPI LdrInitializeThunk( void *kernel_start, ULONG_PTR unknown2,
                                ULONG_PTR unknown3, ULONG_PTR unknown4 )
{
    static const WCHAR globalflagW[] = {'G','l','o','b','a','l','F','l','a','g',0};
    NTSTATUS status;
    WINE_MODREF *wm;
    LPCWSTR load_path;
    SIZE_T stack_size;
    PEB *peb = NtCurrentTeb()->Peb;
    IMAGE_NT_HEADERS *nt = RtlImageNtHeader( peb->ImageBaseAddress );
    static const WCHAR kernel32W[] = 
			{'k','e','r','n','e','l','3','2','.','d','l','l',0};

    wine_dll_set_callback(load_builtin_callback);
    main_exe_file = 0;

	if ((status = load_builtin_dll( NULL, kernel32W, 0, 0, &wm )) != STATUS_SUCCESS)
    {
        MESSAGE( "wine: could not load kernel32.dll, status %x\n", status );
        exit(1);
    }
    if (main_exe_file) NtClose( main_exe_file );  /* at this point the main module is created */

    /* allocate the modref for the main exe (if not already done) */
    wm = get_modref( peb->ImageBaseAddress );
    assert( wm );
    if (wm->ldr.Flags & LDR_IMAGE_IS_DLL)
    {
        ERR("%s is a dll, not an executable\n", debugstr_w(wm->ldr.FullDllName.Buffer) );
        exit(1);
    }

#if 0
    peb->LoaderLock = &loader_section;
    peb->ProcessParameters->ImagePathName = wm->ldr.FullDllName;
    version_init( wm->ldr.FullDllName.Buffer );
#endif

    peb->LoaderLock = &loader_section;
    peb->ProcessParameters->ImagePathName = wm->ldr.FullDllName;
    if (!peb->ProcessParameters->WindowTitle.Buffer)
        peb->ProcessParameters->WindowTitle = wm->ldr.FullDllName;
    version_init( wm->ldr.FullDllName.Buffer );

    LdrQueryImageFileExecutionOptions( &peb->ProcessParameters->ImagePathName, globalflagW,
                                       REG_DWORD, &peb->NtGlobalFlag, sizeof(peb->NtGlobalFlag), NULL );

    /* the main exe needs to be the first in the load order list */
    RemoveEntryList( &wm->ldr.InLoadOrderModuleList );
    InsertHeadList( &peb->LdrData->InLoadOrderModuleList, &wm->ldr.InLoadOrderModuleList );

    stack_size = max( nt->OptionalHeader.SizeOfStackReserve, nt->OptionalHeader.SizeOfStackCommit );
    if (stack_size < 1024 * 1024) stack_size = 1024 * 1024;  /* Xlib needs a large stack */

    if ((status = server_init_process_done()) != STATUS_SUCCESS) goto error;

    /* get process start address from kernel32.dll */
    if (!(BaseProcessStartEntry = (unsigned long) find_builtin_symbol("kernel32.dll", "BaseProcessStart")))
            goto error;

    if (!(process_init = find_builtin_symbol("kernel32.dll", "process_init")))
            goto error;
    
    if (!(ThreadStartup = find_builtin_symbol("kernel32.dll", "ThreadStartup")))
            goto error;
    
    if (!(unhandled_exception_filter = find_builtin_symbol("kernel32.dll", "UnhandledExceptionFilter")))
            goto error;

    process_init();
    actctx_init();

    load_path = NtCurrentTeb()->Peb->ProcessParameters->DllPath.Buffer;
    /* top level, fixup_imports() for the EXE. */
    if ((status = fixup_imports( wm, load_path )) != STATUS_SUCCESS) 
        goto error;
    
    if ((status = alloc_process_tls()) != STATUS_SUCCESS) goto error;
    if ((status = alloc_thread_tls()) != STATUS_SUCCESS) goto error;

    heap_set_debug_flags( GetProcessHeap() );

    status = attach_process_dlls(wm);
    if (status != STATUS_SUCCESS) goto error;

   // if (nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) VIRTUAL_UseLargeAddressSpace();
	virtual_release_address_space( nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE );

	signal(SIGUSR2, NtCatchApc);
    return;

error:
    ERR( "Main exe initialization for %s failed, status %x\n",
         debugstr_w(peb->ProcessParameters->ImagePathName.Buffer), status );
	NtTerminateProcess( GetCurrentProcess(), status );
}

//3.最后调用 NtContinue((PCONTEXT)Context, 1); 恢复PE的上下文，
//这个是load_pe_bianry->start_thread(regs, pe_entry, bprm->p);设置的

NTSTATUS 
SERVICECALL
NtContinue(IN PContext Context,
		IN BOOLEAN TestAlert)
{
	PKTRAP_FRAME trap_frame = (PKTRAP_FRAME)current->ethread->tcb.trap_frame;
       	struct list_head *apc_entry;
       	int count_user = 0;

	ktrace("\n");

 
        apc_entry = current->ethread->tcb.apc_state.apc_list_head[UserMode].next;
        while(apc_entry != &(current->ethread->tcb.apc_state.apc_list_head[UserMode])) {
        	count_user++;
        	apc_entry = apc_entry->next;
 
        }
 
 


       	if(current->ethread->tcb.apc_state.apc_num[UserMode]) {
               set_tsk_thread_flag(current, TIF_APC);
               current->ethread->tcb.apc_state.uapc_pending = 1;

       	}

       	current->ethread->tcb.apc_state.uapc_inprogress = FALSE;


	/*
	 * Copy the supplied context over the register information that was saved
	 * on entry to kernel mode, it will then be restored on exit
	 * FIXME: Validate the context
	 */
	memcpy(trap_frame, Context, sizeof(*trap_frame));

	/* FIXME
	 * Copy floating point context into the thread's FX_SAVE_AREA
	 */

#if 0
	up(&kernel_lock);
#endif
	syscall_lock_up();

	__asm__(
			"andl %%esp, %%ecx;\n\t"
			"movl %%ecx, %%ebp;\n\t"
			"movl %%ebx, %%esp;\n\t"
			"jmp w32syscall_exit\n\t" //跳到w32syscall_exit检查是否需要做apc
			:
			: "b" (trap_frame), "c" (-THREAD_SIZE));

	/* This doesn't actually happen b/c KeRosTrapReturn() won't return */
	return STATUS_SUCCESS;
} /* NtContinue */

//如果没有其他的apc要做的话，w32syscall_exit就会走到start_thread(regs, pe_entry, bprm->p);设置的pe_entry
//pe_entry = get_pe_entry();
//map_system_dll里面:
//	pe_entry = uk_find_symbol(elf_shdata, elf_shnum, "ProcessStartForward");

void ProcessStartForward(unsigned long start_address, void *peb)
{
    BaseProcessStartFunc	BaseProcessStart;

    BaseProcessStart = (BaseProcessStartFunc)BaseProcessStartEntry;
    BaseProcessStart(start_address, peb);
}

//LdrInitializeThunk 里面有:
//    if (!(BaseProcessStartEntry = (unsigned long) find_builtin_symbol("kernel32.dll", "BaseProcessStart")))


//走到了 kernel32.dll
void BaseProcessStart(unsigned long start_address, void *param)
{
    unsigned long   exit_code;
    LPTHREAD_START_ROUTINE  entry;

    SERVER_START_REQ( new_thread )
    {
		int ret=0;
        req->operation = 0;
		ret = wine_server_call_err( req );
		if(ret)
		{
			ERR("new_thread error\n");
			return;
		}
    }
   SERVER_END_REQ;

    __TRY
    {
        entry = (LPTHREAD_START_ROUTINE)start_address;
        exit_code = entry(param);//终于走到PE入口执行了
    }
    __EXCEPT(UnhandledExceptionFilter)
    {
        exit_code = GetExceptionCode();
    }
    __ENDTRY;
    ExitProcess(exit_code);
}
