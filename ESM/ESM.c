 /**
 * Event Stream Model (ESM): Push model for input events.
 * Currently only works for certain mouse events.
 *
 * Dustin Colten McAfee <dmcafee2@my.utk.edu> <dustin.mcafee@my.maryvillecollege.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 **/


#include <linux/input.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h> //copy_to_user
#include <linux/interrupt.h> //for tasklets
#include <ESM.h>

//Module Stuff:
//#include <linux/init.h>
//#include <linux/module.h>

//MODULE_LICENSE(“GPL”);
//MODULE_AUTHOR(“Dustin C. McAfee”);
//MODULE_DESCRIPTION(“Event Stream Model Kernel Module”);
//MODULE_VERSION(“0.01”);

application_l mouse_rel_x_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_x_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_rel_y_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_y_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_rel_wheel_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_wheel_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_rel_hwheel_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_hwheel_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_btn_left_handlers = {
	.list = LIST_HEAD_INIT(mouse_btn_left_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_btn_right_handlers = {
	.list = LIST_HEAD_INIT(mouse_btn_right_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_btn_middle_handlers = {
	.list = LIST_HEAD_INIT(mouse_btn_middle_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l emu_mouse_btn_left_handlers = {
	.list = LIST_HEAD_INIT(emu_mouse_btn_left_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l no_handlers = {
	.list = LIST_HEAD_INIT(no_handlers.list),
	.event_handler = 0,
	.event_keycode = APPLICATION_LIST_SIZE
};

application_list_t application_list = {
	.mouse_rel_x_handlers = &mouse_rel_x_handlers,
	.mouse_rel_y_handlers = &mouse_rel_y_handlers,
	.mouse_rel_wheel_handlers = &mouse_rel_wheel_handlers,
	.mouse_rel_hwheel_handlers = &mouse_rel_hwheel_handlers,
	.mouse_btn_left_handlers = &mouse_btn_left_handlers,
	.mouse_btn_right_handlers = &mouse_btn_right_handlers,
	.mouse_btn_middle_handlers = &mouse_btn_middle_handlers,
	.emu_mouse_btn_left_handlers = &emu_mouse_btn_left_handlers,
	.no_handlers = &no_handlers
};

esm_tasklet_data tasklet_data = {
	.event = NULL,
	.application = &no_handlers
};

application_l* handlers_for_event(esm_event_t keycode){
	application_l* application;
	switch (keycode){
	case MOUSE_RELATIVE_X:
		application = application_list.mouse_rel_x_handlers;
		break;
	case MOUSE_RELATIVE_Y:
		application = application_list.mouse_rel_y_handlers;
		break;
	case MOUSE_RELATIVE_WHEEL:
		application = application_list.mouse_rel_wheel_handlers;
		break;
	case MOUSE_RELATIVE_HWHEEL:
		application = application_list.mouse_rel_hwheel_handlers;
		break;
	case MOUSE_BUTTON_LEFT:
		application = application_list.mouse_btn_left_handlers;
		break;
	case MOUSE_BUTTON_RIGHT:
		application = application_list.mouse_btn_right_handlers;
		break;
	case MOUSE_BUTTON_MIDDLE:
		application = application_list.mouse_btn_middle_handlers;
		break;
	case EMU_MOUSE_BUTTON_LEFT:
		application = application_list.emu_mouse_btn_left_handlers;
		break;
	default:
		application = application_list.no_handlers;
		break;
	}
	return application;
}

esm_event_t esm_keycode_from_input(__u16 type, __u16 code){
        esm_event_t event_keycode = APPLICATION_LIST_SIZE;
        if(type == EV_REL){
                switch (code) {
                case REL_X:
                        event_keycode = MOUSE_RELATIVE_X;
                        break;
                case REL_Y:
                        event_keycode = MOUSE_RELATIVE_Y;
                        break;
                case REL_WHEEL:
                        event_keycode = MOUSE_RELATIVE_WHEEL;
                        break;
                case REL_HWHEEL:
                        event_keycode = MOUSE_RELATIVE_HWHEEL;
                        break;
                }
        } else if(type == EV_KEY){
                switch (code) {
                case BTN_LEFT:
                        event_keycode = MOUSE_BUTTON_LEFT;
                        break;
                case BTN_RIGHT:
                        event_keycode = MOUSE_BUTTON_RIGHT;
                        break;
                case BTN_MIDDLE:
                        event_keycode = MOUSE_BUTTON_MIDDLE;
                        break;
                }
        } else if(type == 3 && code == 57) {
		event_keycode = EMU_MOUSE_BUTTON_LEFT;
        }
        return event_keycode;
}

int esm_register(pid_t pid, __u16 type, __u16 code, uintptr_t event_handler_user) {
	//If event_handler == NULL
	//	delete application_list[event][application]
	//else
	//	application_list[event][application] = event_handler
	application_l *application_category, *application;
	struct list_head *pos, *q;
	esm_event_t event_keycode;
	uintptr_t event_handler = event_handler_user;
	struct task_struct* task = current;

	printk(KERN_WARNING "esm_register (pid: %d), (handler virtual address: 0x%08x)\n", task->pid, event_handler);

	event_keycode = esm_keycode_from_input(type, code);
	if(event_keycode == APPLICATION_LIST_SIZE){
		pr_err("Invalid event to register\n");
		return -EINVAL;
	}
	application_category = handlers_for_event(event_keycode);

	if(!event_handler){
		//Delete all handlers for this event
		spin_lock(&application_category->lock);
		list_for_each_safe(pos, q, &(application_category->list)){
			application = list_entry(pos, application_l, list);
			list_del(pos);
			kfree(application);
		}
		//free application_list[input_value][task->pid];
	}else{
		//application_list[input_value][task->pid] = event_handler;
		application = kmalloc(sizeof(application_l), GFP_KERNEL);

		spin_lock(&application_category->lock);
		application->event_keycode = event_keycode;
		application->task = task;
		application->event_handler = event_handler;

		//Add application (event_handler) to corresponding application list (list of categorized event handlers)
		list_add(&(application->list), &(application_category->list));
	}
	spin_unlock(&application_category->lock);
	return 0;
}

int esm_register1(pid_t pid, __u16 type, __u16 code, uintptr_t event_handler) {
	return esm_register(pid, type, code, event_handler);
}

//Call handler (not like this but to the effect): application->event_handler(event->type, event->code, event->value);
//TODO:Fails here. How to call userspace function?
/**
According to the ABI, the first 6 integer or pointer arguments to a function are passed in registers.
The first is placed in edi/rdi, the second in esi/rsi, the third in edx/rdx, and then ecx/rcx, r8 and r9.
Only the 7th argument and onwards are passed on the stack. Should be at ebp+8 and on (8 byte aligned).
The return address that should be set to the event_handler should be at ebp+4 of the correct stack frame.
"movl [handler], %%eax\n\t"
"call *%eax\n\t"

"call *%0\n\t"
"call *%[handler]\n\t"

**/


#ifdef CONFIG_X86_32
#define handle_event(handler_address, err)				\
do {									\
	asm volatile("pushfl\n\t"		/* save    flags */	\
		     "pushl %%ebp\n\t"		/* save    EBP   */	\
		     "movl %%esp, %%ebp\n\t"	/* save    ESP   */	\
                     "movl %[handler], %%eax\n\t"			\
                     "call *%eax\n\t"					\
                     "movl $0, %%eax\n\t"	/* move 0 to eax */	\
                     "popl %%ebp\n\t"		/* restore ebp   */	\
                     "popfl\n"			/* restore flags */	\
                     "ret\n\t"			/* return	 */	\
                     : "=i" (err) : [handler] "r" (handler_address));		\
} while (0)

#else

#define handle_event(handler_address, err)				\
	asm volatile("pushf\n\t"		/* save    flags */	\
		     "pushq %%rbp\n\t"		/* save    RBP   */	\
		     "movq %%rsp, %%rbp\n\t"	/* save    RSP   */	\
                     "call *%[handler]\n\t"				\
                     "movq $0, %%rax\n\t"	/* move 0 to rax */	\
                     "popq %%rbp\n\t"		/* pop rbp       */	\
                     "popf\n"			/* restore flags */	\
                     "ret\n\t"			/* return	 */	\
                     : "=r" (err) : [handler] "r" (handler_address));
#endif

int esm_dispatch(struct input_value* event, application_l* application){
	//If task->state == TASK_EV_WAIT
	//	task->state = TASK_RUNNUNG
	//	handler = application_list[event][application]
	//	handler(event)
	//else
	//	application.enqueue(event);
	struct event_queue_t* event_queue_item;
	int err = 0;

	printk(KERN_WARNING "esm_dispatch is adding the registered event to event queue, pid: %d\n", application->task->pid);

	//This lock applies for application handlers associated with a specific input value
	event_queue_item = kmalloc(sizeof(struct event_queue_t), GFP_KERNEL);
	spin_lock(&application->task->event_queue_lock);
	event_queue_item->event = event;
	list_add(&(event_queue_item->event_queue), &(application->task->event_queue.event_queue));
	spin_unlock(&application->task->event_queue_lock);

	printk(KERN_WARNING "Event Added!\n");

	if(application->task->state == TASK_EV_WAIT){
		printk(KERN_WARNING "esm_dispatch attempting to wake up process: %d\n", application->task->pid);
		if(wake_up_state(application->task, TASK_EV_WAIT) == 1){	//Less overhead to directly assign task->state = TASK_RUNNING
			printk(KERN_WARNING "esm_dispatch: has waken up process %d; task now in state %ld\n", application->task->pid, application->task->state);
		}else{
			printk(KERN_WARNING "esm_dispatch can not wake up process %d, already running\n", application->task->pid);
			err = -1;
		}
	}

	return err;
}

int _handle_events(void __user *event_buffer, void __user *handler_buffer){
	application_l *application_category, *application;
	esm_event_t ev_keycode;
	struct list_head *pos_one, *pos, *q, *qq;
	struct event_queue_t* ev_queue;
	struct input_value* event;
	uintptr_t handler_address;
	struct task_struct* task;
	int err = 0;
	bool copied = false;
	task = current;

	if(list_empty(&(task->event_queue.event_queue))){
		printk(KERN_ERR "No events to handle, pid: %d\n", task->pid);
		return -1;
	}

	//For each event TODO: Does this grab the first element or should I use
	//ev_queue = list_first_entry(&(task->event_queue.event_queue), struct event_queue_t, event_queue);
	list_for_each_safe(pos_one, q, &(task->event_queue.event_queue)){
		ev_queue = list_entry(pos_one, struct event_queue_t, event_queue);
		printk(KERN_WARNING "Handling events, pid: %d\n", task->pid);
		event = ev_queue->event;
		ev_keycode = esm_keycode_from_input(event->type, event->code);
		if(ev_keycode != APPLICATION_LIST_SIZE){
			application_category = handlers_for_event(ev_keycode);

			// For each application handler of same event
			list_for_each_safe(pos, qq, &(application_category->list)){
				application = list_entry(pos, application_l, list);
				if(application->task->pid == task->pid){
					handler_address = application->event_handler;
					printk(KERN_WARNING "_handle_events: HANDLER Virtual ADDRESS: 0x%012x\n", handler_address);

					if(copy_to_user(event_buffer, event, sizeof(struct input_value)) || copy_to_user(handler_buffer, &handler_address, sizeof(uintptr_t))){
						printk(KERN_ERR "_handle_events: Failed to Copy Event to User Supplied Buffer\n");
						err = -EINVAL;
					} else {
						copied = true;
					}

					// Delete Application Handler
					printk(KERN_WARNING "Removing event handler from pid: %d\n", task->pid);
					spin_lock(&application_category->lock);
					list_del(pos);
					kfree(application);
					spin_unlock(&application_category->lock);

					// Delete the Handled Event
					printk(KERN_WARNING "Removing handled event from pid: %d\n", task->pid);
					spin_lock(&task->event_queue_lock);
					list_del(pos_one);
					kfree(event);
					kfree(ev_queue);
					spin_unlock(&task->event_queue_lock);
//					handle_event(handler_address, err_out);		// TODO: Does not work; would like to accomplish something to this affect.
					goto esm_out;		//Handle one at a time. Later should implement copying array of values to user space.
					//TODO: FIXME: Should really copy multiple to userspace and delete what is not copied, otherwise the
					//programmer would have to call esm_register/esm_wait in a loop to fish out all queued input values.
				}
			}
		}
	}
esm_out:
	if(err >= 0 && !copied){
		err = -1;
	}
	return err;
}


int esm_wait(pid_t pid, void __user *event_buffer, void __user *handler_buffer){
//	if(task->event_queue.empty()){
//		task->state = TASK_EV_WAIT;
//	} else {
//		event = task->event_queue.pop();
//		task->state = TASK_EV_WAIT;
//		esm_dispatch(event, task);
//	}
	printk(KERN_WARNING "esm_wait: %d\n", pid);

	if(list_empty(&(current->event_queue.event_queue))){
		printk(KERN_WARNING "esm_wait: event_queue is empty, scheduling task\n");
		set_task_state(current, TASK_EV_WAIT);		//TODO: Make sure this is interruptible
		schedule();
	}

	return _handle_events(event_buffer, handler_buffer);
}

int esm_wait1(pid_t pid, void __user *event_buffer, void __user *handler_buffer){
	return esm_wait(pid, event_buffer, handler_buffer);
}

void __esm_dispatch(esm_tasklet_data* tasklet_data){
	esm_dispatch(tasklet_data->event, tasklet_data->application);
}

DECLARE_TASKLET(esm_dispatch_tasklet, __esm_dispatch, &tasklet_data);

int esm_interpret(struct input_value* ev){
	//foreach application in application_list
	//	esm_dispatch(event, application)
	struct list_head *pos, *q;
	application_l *application, *application_category;
	esm_event_t ev_keycode;
	struct input_value* event;

	printk(KERN_WARNING "Call to ESM Interpret\n");

	event = kmalloc(sizeof(struct input_value), GFP_ATOMIC);	//in interrupt context => use GFP_ATOMIC
	memcpy(event, ev, sizeof(struct input_value));			//We need this to stay in memory until we copy_to_user

	ev_keycode = esm_keycode_from_input(event->type, event->code);
	if(ev_keycode == APPLICATION_LIST_SIZE){
		printk(KERN_ERR "Invalid event being interpreted\n");
		return -EINVAL;
	}

	application_category = handlers_for_event(ev_keycode);

	//Check if nothing registered
	if(list_empty(&(application_category->list))){
		return 0;
	}

	//Dispatch for each registered application handler
	list_for_each_safe(pos, q, &(application_category->list)){
		application = list_entry(pos, application_l, list);
		tasklet_data.application = application;
		tasklet_data.event = event;
		//Use Tasklet so that we may kmalloc GFP_KERNEL events and add to event queue for task
		tasklet_schedule(&esm_dispatch_tasklet);
	}
	return 0;
}

/*
static int __init esm_init(void) {

 printk(KERN_WARNING "ESM_INIT\n");
 return 0;
}

static void __exit esm_exit(void) {
 printk(KERN_INFO "ESM_EXIT\n");
}

module_init(esm_init);
module_exit(esm_exit);
*/

//asmlinkage long sys_esm_register(pid_t pid, __u16 type, __u16 code, event_handler_t event_handler) {
//	struct input_value event;
//	event.type = type;
//	event.code = code;
//
//	return esm_register(pid, event, event_handler);
//}

//asmlinkage long sys_esm_wait(pid_t pid) {
//	return esm_wait(pid);
//}

//typedef void (*event_handler_t)(__u16, __u16, __s32);
//SYSCALL_DEFINE4(esm_register, pid_t, pid, __u16, type, __u16, code, event_handler_t, event_handler){
//	return esm_register(pid, event, event_handler);
//}
//SYSCALL_DEFINE1(esm_wait, pid_t, pid){
//	return esm_wait(pid);
//}

