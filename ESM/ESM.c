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


#include <linux/input.h>	//struct input_value
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/uaccess.h> //copy_to_user
#include <linux/interrupt.h> //for tasklets
#include <linux/file.h>	//for struct fd and fd[get|put]
#include <uapi/linux/kd.h>	//for KDGETKEYCODE
#include <linux/eventfd.h>	//for eventfd_get
#include <ESM.h>

//Module Stuff:
//#include <linux/init.h>
//#include <linux/module.h>

//MODULE_LICENSE(“GPL”);
//MODULE_AUTHOR(“Dustin C. McAfee”);
//MODULE_DESCRIPTION(“Event Stream Model Kernel Module”);
//MODULE_VERSION(“0.01”);

#define ESM_MAX_EVENTS 128

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
application_l unknown_key_handlers = {
	.list = LIST_HEAD_INIT(unknown_key_handlers.list),
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
	.unknown_key_handlers = &unknown_key_handlers,
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
	case UNKNOWN_KEY:
		application = application_list.unknown_key_handlers;
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
		default:
			event_keycode = UNKNOWN_KEY;
			break;
                }
        } else if(type == 3 && code == 57) {
		event_keycode = EMU_MOUSE_BUTTON_LEFT;
        }
        return event_keycode;
}


#include <linux/cdev.h>
#include <linux/wakelock.h>
struct evdev {
        int open;
        struct input_handle handle;
        wait_queue_head_t wait;
        struct evdev_client __rcu *grab;
        struct list_head client_list;
        spinlock_t client_lock; /* protects client_list */
        struct mutex mutex;
        struct device dev;
        struct cdev cdev;
        bool exist;
};

struct evdev_client {
        unsigned int head;
        unsigned int tail;
        unsigned int packet_head; /* [future] position of the first element of next packet */
        spinlock_t buffer_lock; /* protects access to buffer, head and tail */
        struct wake_lock wake_lock;
        bool use_wake_lock;
        char name[28];
        struct fasync_struct *fasync;
        struct evdev *evdev;
        struct list_head node;
        int clkid;
        unsigned int bufsize;
        struct input_event buffer[];
};

int esm_register(uint8_t* __user evtype_bitmask, pid_t pid, __u16 type, __u16 code, uintptr_t event_handler_user) {
	//If event_handler == NULL
	//	delete application_list[event][application]
	//else
	//	application_list[event][application] = event_handler
	application_l *application_category, *application;
	struct list_head *pos, *q;
	esm_event_t event_keycode;
        uint8_t evbitmask[EV_MAX/8 + 1];
	uintptr_t event_handler = event_handler_user;
	struct task_struct* task = find_task_by_vpid(pid);
	int i = 0;

	printk(KERN_DEBUG "esm_register (pid: %d), (handler virtual address: 0x%08x)\n", task->pid, event_handler);



        copy_from_user(evbitmask, evtype_bitmask, sizeof(evbitmask));

	//This works; TODO: Implement for event codes, and use to register events.
	while(i < EV_MAX){
		if (!test_bit(i, evbitmask))
			continue;

		printk(KERN_INFO "  Event type 0x%02x\n", i);

		switch (i) {

		case EV_KEY :
			printk(KERN_INFO " (Keys or Buttons)\n");
			break;
		case EV_REL :
			printk(KERN_INFO " (Relative Axes)\n");
			break;
		case EV_ABS :
			printk(KERN_INFO " (Absolute Axes)\n");
			break;
		case EV_MSC :
			printk(KERN_INFO " (Something miscellaneous)\n");
			break;
		case EV_LED :
			printk(KERN_INFO " (LEDs)\n");
			break;
		case EV_SND :
			printk(KERN_INFO " (Sounds)\n");
			break;
		case EV_REP :
			printk(KERN_INFO " (Repeat)\n");
			break;
		case EV_FF :
			printk(KERN_INFO " (Force Feedback)\n");
			break;
		default:
			printk(KERN_INFO " (Unknown event type: 0x%04x)\n", i);
			break;
		}
	i = i + 1;
	}






	event_keycode = esm_keycode_from_input(type, code);
	if(event_keycode == APPLICATION_LIST_SIZE){
		printk(KERN_ERR "Invalid event to register\n");
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
			task->registered_handlers -= 1;
		}
		//free application_list[input_value][task->pid];
	}else{
		//application_list[input_value][task->pid] = event_handler;
		application = kmalloc(sizeof(application_l), GFP_KERNEL);

		spin_lock(&application_category->lock);
		application->event_keycode = event_keycode;
		application->task = task;
		application->event_handler = event_handler;
		task->registered_handlers += 1;

		//Add application (event_handler) to corresponding application list (list of categorized event handlers)
		list_add(&(application->list), &(application_category->list));
	}
	spin_unlock(&application_category->lock);
	return 0;
}

int esm_register1(uint8_t* __user evtype_bitmask, pid_t pid, __u16 type, __u16 code, uintptr_t event_handler) {
	return esm_register(evtype_bitmask, pid, type, code, event_handler);
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

	printk(KERN_DEBUG "esm_dispatch is adding the registered event to event queue, pid: %d\n", application->task->pid);

	//This lock applies for application handlers associated with a specific input value
	event_queue_item = kmalloc(sizeof(struct event_queue_t), GFP_KERNEL);
	spin_lock(&application->task->event_queue_lock);
	event_queue_item->event = event;
	list_add(&(event_queue_item->event_queue), &(application->task->event_queue.event_queue));
	spin_unlock(&application->task->event_queue_lock);

	printk(KERN_DEBUG "Event Added!\n");

	if(application->task->state == TASK_EV_WAIT){
		printk(KERN_DEBUG "esm_dispatch attempting to wake up process: %d\n", application->task->pid);
		if(wake_up_state(application->task, TASK_EV_WAIT) == 1){	//Less overhead to directly assign task->state = TASK_RUNNING
			printk(KERN_DEBUG "esm_dispatch: has waken up process %d; task now in state %ld\n", application->task->pid, application->task->state);
		}else{
			printk(KERN_DEBUG "esm_dispatch can not wake up process %d, already running\n", application->task->pid);
			err = -1;
		}
	}

	return err;
}

int _handle_events(struct task_struct* task, void __user *event_buffer, void __user *handler_buffer){
	application_l *application_category, *application;
	esm_event_t ev_keycode;
	struct list_head *pos_one, *pos, *q;
	struct event_queue_t* ev_queue;
	struct input_value* event;
	uintptr_t handler_address;
	int err = 0;
	int ret = 0;

	if(list_empty(&(task->event_queue.event_queue))){
		printk(KERN_ERR "No events to handle, pid: %d\n", task->pid);
		return -1;
	}

	//For each event TODO: Does this grab the first element or should I use
	//ev_queue = list_first_entry(&(task->event_queue.event_queue), struct event_queue_t, event_queue);
	list_for_each_safe(pos_one, q, &(task->event_queue.event_queue)){
		ev_queue = list_entry(pos_one, struct event_queue_t, event_queue);
		printk(KERN_DEBUG "Handling events, pid: %d\n", task->pid);
		event = ev_queue->event;
		ev_keycode = esm_keycode_from_input(event->type, event->code);
		if(ev_keycode != APPLICATION_LIST_SIZE){
			application_category = handlers_for_event(ev_keycode);

			// For each application handler of same event
			list_for_each(pos, &(application_category->list)){
				application = list_entry(pos, application_l, list);
				if(application->task->pid == task->pid){
					handler_address = application->event_handler;
					printk(KERN_DEBUG "_handle_events: HANDLER Virtual ADDRESS: 0x%012x\n", handler_address);

					if(ret >= ESM_MAX_EVENTS){goto esm_out;}

					if(copy_to_user(event_buffer, event, sizeof(struct input_value)) || copy_to_user(handler_buffer, &handler_address, sizeof(uintptr_t))){
						printk(KERN_ERR "_handle_events: Failed to Copy Event to User Supplied Buffer\n");
						err = -EINVAL;
						goto esm_out;
					} else {
						ret += 1;
						event_buffer += sizeof(struct input_value);
						handler_buffer += sizeof(uintptr_t);
					}

					// Delete the Handled Event
					printk(KERN_DEBUG "Removing handled event from pid: %d\n", task->pid);
					spin_lock(&task->event_queue_lock);
					list_del(pos_one);
					kfree(event);
					kfree(ev_queue);
					spin_unlock(&task->event_queue_lock);
				}
			}
		}
	}
esm_out:
	if(err < 0){ret = err;}
	return ret;
}


int esm_wait(pid_t pid, void __user *event_buffer, void __user *handler_buffer){
//	if(task->event_queue.empty()){
//		task->state = TASK_EV_WAIT;
//	} else {
//		event = task->event_queue.pop();
//		task->state = TASK_EV_WAIT;
//		esm_dispatch(event, task);
//	}
	bool registered = false;
	struct task_struct *task = find_task_by_vpid(pid);

	printk(KERN_DEBUG "esm_wait: %d\n", pid);

	if(!task->registered_handlers){
		printk(KERN_ERR "esm_wait: No registered event handlers\n");
		return -1;
	}

	if(list_empty(&(task->event_queue.event_queue))){
		printk(KERN_DEBUG "esm_wait: event_queue is empty, scheduling task\n");
		set_task_state(task, TASK_EV_WAIT);		//TODO: Make sure this is interruptible
		schedule();
	}

	return _handle_events(task, event_buffer, handler_buffer);
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
	struct list_head *pos;
	application_l *application, *application_category;
	esm_event_t ev_keycode;
	struct input_value* event;

	printk(KERN_DEBUG "Call to ESM Interpret\n");

	ev_keycode = esm_keycode_from_input(ev->type, ev->code);
	if(ev_keycode == APPLICATION_LIST_SIZE){return 0;}

	application_category = handlers_for_event(ev_keycode);
	if(list_empty(&(application_category->list))){return 0;}

	//Create copy of event into memory (TODO: May not be completely necessary)
	event = kmalloc(sizeof(struct input_value), GFP_ATOMIC);	//in interrupt context => use GFP_ATOMIC
	memcpy(event, ev, sizeof(struct input_value));			//We need this to stay in memory until we copy_to_user

	//Dispatch for each registered application handler
	list_for_each(pos, &(application_category->list)){
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

