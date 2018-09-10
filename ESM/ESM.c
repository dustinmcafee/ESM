/*
 * Event Stream Model (ESM): Push model for input events.
 * Currently only works for certain mouse events.
 *
 * Dustin Colten McAfee <dmcafee2@my.utk.edu> <dustin.mcafee@my.maryvillecollege.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */


#include <linux/input.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
//#include <linux/uaccess.h> //copy_from_user
#include <linux/interrupt.h> //for tasklets
#include <ESM.h>
//#include <linux/syscalls.h>

//Module Stuff:
//#include <linux/init.h>
//#include <linux/module.h>

//MODULE_LICENSE(“GPL”);
//MODULE_AUTHOR(“Dustin C. McAfee”);
//MODULE_DESCRIPTION(“Event Stream Model Kernel Module”);
//MODULE_VERSION(“0.01”);

application_l mouse_rel_x_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_x_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_rel_y_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_y_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_rel_wheel_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_wheel_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_rel_hwheel_handlers = {
	.list = LIST_HEAD_INIT(mouse_rel_hwheel_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_btn_left_handlers = {
	.list = LIST_HEAD_INIT(mouse_btn_left_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_btn_right_handlers = {
	.list = LIST_HEAD_INIT(mouse_btn_right_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l mouse_btn_middle_handlers = {
	.list = LIST_HEAD_INIT(mouse_btn_middle_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l emu_mouse_btn_left_handlers = {
	.list = LIST_HEAD_INIT(emu_mouse_btn_left_handlers.list),
	.event_handler = NULL,
	.event_keycode = APPLICATION_LIST_SIZE
};
application_l no_handlers = {
	.list = LIST_HEAD_INIT(no_handlers.list),
	.event_handler = NULL,
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
	.code = NULL,
	.type = NULL,
	.value = NULL,
	.task = NULL
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

//esm_event_t esm_keycode_from_input(struct input_value* event){
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

int esm_register(pid_t pid, __u16 type, __u16 code, __user event_handler_t event_handler_user) {
	//If event_handler == NULL
	//	delete application_list[event][application]
	//else
	//	application_list[event][application] = event_handler
	application_l *application_category, *application;
	struct list_head *pos, *q;
	struct task_struct* task;
	esm_event_t event_keycode;

	event_handler_t event_handler = event_handler_user;
	task = current;

	printk(KERN_WARNING "esm_register: %d\n", task->pid);
	if(task == NULL){
		pr_err("Can not esm_register, task is NULL\n");
		return -EINVAL;
	}

	event_keycode = esm_keycode_from_input(type, code);
	if(event_keycode == APPLICATION_LIST_SIZE){
		pr_err("Invalid event to register\n");
		return -EINVAL;
	}

	application_category = handlers_for_event(event_keycode);
	spin_lock(&application_category->lock);
	if(event_handler == NULL){
		list_for_each_safe(pos, q, &(application_category->list)){
			application = list_entry(pos, application_l, list);
			if(application->event_handler == event_handler){
				list_del(pos);
			}
			kfree(application);
		}
		//free application_list[input_value][task->pid];
	}else{
		//application_list[input_value][task->pid] = event_handler;
		application = kmalloc(sizeof(application_l*), GFP_KERNEL);

		application->event_keycode = event_keycode;
		application->task = task;
		application->event_handler = event_handler;

		//Add application (event_handler) to corresponding application list (list of categorized event handlers)
		list_add(&(application->list), &(application_category->list));
	}
	spin_unlock(&application_category->lock);
	return 0;
}

int esm_register1(pid_t pid, __u16 type, __u16 code, __user event_handler_t event_handler) {
	return esm_register(pid, type, code, event_handler);
}

int esm_dispatch(struct input_value* event, struct task_struct* task){
	//If task->state == TASK_EV_WAIT
	//	task->state = TASK_RUNNUNG
	//	handler = application_list[event][application]
	//	handler(event)
	//else
	//	application.enqueue(event);
	application_l *application_category;
	esm_event_t ev_keycode;
//	struct task_struct* prev;
	struct event_queue_t* event_queue_item;
	int dbg_pid = task->pid;

	printk(KERN_WARNING "esm_dispatch pid: %d\n", dbg_pid);

	ev_keycode = esm_keycode_from_input(event->type, event->code);
	application_category = handlers_for_event(ev_keycode);
	spin_lock(&application_category->lock);				//TODO: Is this appropriate location?

	if(task->state == TASK_EV_WAIT){
		struct list_head* pos;
		application_l *application;

		if(ev_keycode == APPLICATION_LIST_SIZE){
			pr_err("Invalid event to dispatch\n");
			return -EINVAL;
		}

		list_for_each(pos, &(application_category->list)){
			application = list_entry(pos, application_l, list);
			if(application->task->pid == dbg_pid){
				printk(KERN_WARNING "esm_dispatch attempting to wake up process: %d\n", dbg_pid);

				if(wake_up_state(task, TASK_EV_WAIT) == 1){	//Less overhead to directly assign task->state = TASK_RUNNING

					printk(KERN_WARNING "esm_dispatch has waken up process: %d\n", dbg_pid);
					printk(KERN_WARNING "esm_dispatch: process: %d is in state: %ld\n", dbg_pid, task->state);

					//Context Switch Function Here.
//					prev = current;
//					switch_to(prev, task, prev);
					if(esm_context_switch(task) < 0){
						printk(KERN_WARNING "esm_context_switch error");
					}
//					application->event_handler(event->type, event->code, event->value);	//TODO:Fails here. How to call userspace function?
					//Force a Context Switch here...Change esp to new return address. Possibly add input_event arguements to esp+8?
					struct pt_regs *regs = task_pt_regs(task);
//					regs->cr_iip = application->event_handler;
					regs->ip = application->event_handler;

				}else{
					pr_err("esm_dispatch can not wake up process %d, already running\n", dbg_pid);
				}
				break;
			}else{
				printk(KERN_WARNING "esm_dispatch could not dicipher the task struct from the list, pid: %d\n", application->task->pid);
			}
		}
	} else {
		printk(KERN_WARNING "esm_dispatch is adding the registered event to event queue, pid: %d\n", dbg_pid);

		event_queue_item = kmalloc(sizeof(struct event_queue_t*), GFP_KERNEL);

//		spin_lock(&event_queue_item->lock);	//causes deadlock

		event_queue_item->event = event;
		list_add(&(event_queue_item->event_queue), &(task->event_queue));

//		spin_unlock(&event_queue_item->lock);
	}

	spin_unlock(&application_category->lock);
	return 0;
}

int esm_wait(pid_t pid){
//	if(task->event_queue.empty()){
//		task->state = TASK_EV_WAIT;
//	} else {
//		event = task->event_queue.pop();
//		task->state = TASK_EV_WAIT;
//		esm_dispatch(event, task);
//	}

	struct list_head *pos, *q;
	struct event_queue_t* ev_queue;
	struct input_value* event;
	struct task_struct* task;
	int err = 0;

	printk(KERN_WARNING "esm_wait: %d\n", pid);
        task = current;
        if(task == NULL){
                pr_err("Can not esm_wait, task is NULL\n");
		return -EINVAL;
        }

	set_task_state(task, TASK_EV_WAIT);
	if(list_empty(&(task->event_queue))){
		printk(KERN_WARNING "esm_wait: event_queue is empty, scheduling task\n");
		schedule();
	}else{
		list_for_each_safe(pos, q, &(task->event_queue)){
			printk(KERN_WARNING "esm_wait: event_queue is not empty, scheduling event\n");
			ev_queue = list_entry(pos, struct event_queue_t, event_queue);
			spin_lock(&ev_queue->lock);
			event = ev_queue->event;
			err = esm_dispatch(event, task);
			list_del(pos);
			kfree(ev_queue);
			spin_unlock(&ev_queue->lock);
		}
	}
	return err;
}

int esm_wait1(pid_t pid){
	return esm_wait(pid);
}

void __esm_dispatch(esm_tasklet_data* tasklet_data){
	struct task_struct* task;
	struct input_value event;

	task = tasklet_data->task;
	event.type = tasklet_data->type;
	event.code = tasklet_data->code;
	event.value = tasklet_data->value;

	esm_dispatch(&event, task);
}

DECLARE_TASKLET(esm_dispatch_tasklet, __esm_dispatch, &tasklet_data);

int esm_interpret(struct input_value* event){
	//foreach application in application_list
	//	esm_dispatch(event, application)
	struct list_head* pos;
	struct task_struct* task;
	application_l *application, *application_category;
	esm_event_t ev_keycode;
	int err = 0;

	printk(KERN_WARNING "Call to ESM Interpret\n");

	ev_keycode = esm_keycode_from_input(event->type, event->code);
	if(ev_keycode == APPLICATION_LIST_SIZE){
		pr_err("Invalid event being interpreted\n");
		return -EINVAL;
	}

	application_category = handlers_for_event(ev_keycode);
	list_for_each(pos, &(application_category->list)){
		application = list_entry(pos, application_l, list);
		task = application->task;

		tasklet_data.task = task;
		tasklet_data.type = event->type;
		tasklet_data.code = event->code;
		tasklet_data.value = event->value;
		tasklet_schedule(&esm_dispatch_tasklet);
//		err = esm_dispatch(event, task);
	}
	return err;
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

