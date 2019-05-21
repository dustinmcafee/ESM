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


// TODO: Change all instances of input_value to input_event, include timestamp in evdev.c when invoking esm_interpret
// TODO: Change the linked-list added to task_struct in sched.h to a kfifo. This may help with the input jitters.

#include <linux/input.h>	//struct input_value
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/eventpoll.h>	//struct epoll_event
#include <linux/uaccess.h>	//copy_to_user
#include <ESM.h>

application_l root_devices = {
	.list = LIST_HEAD_INIT(root_devices.list)
};

/**
 * Checks if input_id structures are equal
 *
 * id_one: first input_id to check
 * id_two: second input_id to check
 *
 * Return: 1 if equal, 0 otherwise
 */
int input_id_equal(struct input_id id_one, struct input_id id_two){
	if(id_one.bustype == id_two.bustype &&
		id_one.vendor == id_two.vendor &&
		id_one.product == id_two.product &&
		id_one.version == id_two.version){
		return 1;
	}
	return 0;
}

/**
 * Traverse application list and find matching device and task_struct
 * id: input device to look for
 * task: task_struct associated with input_id
 *
 * Return application_l corresponding to device or root_devices if doesn't exist
 */
application_l* application_from_input_id(struct input_id id, struct task_struct* task) {
	application_l* app;
	struct list_head *pos;
	if(!list_empty(&root_devices.list)){
		list_for_each(pos, &(root_devices.list)){
			app = list_entry(pos, application_l, list);
			if(input_id_equal(app->id, id) && app->task == task) {
				return app;
			}
		}
	}
	return &root_devices;
}

/**
 * Traverse the event_queue in the given task struct and print event_values
 *
 * task: Process Control Block to traverse
 */
void print_debug_task_event_queue(struct task_struct *task) {
	struct event_queue_t* ev_queue;
	struct input_value* event;
	struct list_head *pos;

	if(list_empty(&(task->event_queue.event_queue))){
		return;
	}

	//For each event in the task's event queue
	list_for_each(pos, &(task->event_queue.event_queue)){
		ev_queue = list_entry(pos, struct event_queue_t, event_queue);
		event = ev_queue->event;

		// Print Event
		printk(KERN_DEBUG "Task pid: %d, Event Type: %d, Event Code: %d, Event Value: %d\n", task->pid, event->type, event->code, event->value);
	}
}

/**
 * Register ESM to process (pid)
 * id: input device to register/deregister
 * pid: process to register/deregister to/from
 * reg: 1 to register, 0 to deregister
 *
 * Return: 0 on success, -1 on failure, or -ENOMEM if kmalloc fails
 */
int esm_register(void __user* inid, pid_t pid, void __user* epoll_item, int reg) {
	application_l *application;
	struct input_id id;
	struct workqueue_struct *wq;
	char wq_name[20];
	struct epoll_event epoll_e;
	struct task_struct* task = find_task_by_vpid(pid);
	if(copy_from_user(&id, inid, sizeof(struct input_id)) < 0){
		printk(KERN_ERR "esm_register could not copy device input id to struct input_id\n");
		return -1;
	}

	if(!reg && !list_empty(&(root_devices.list))){
		// Delete (Unregister) all handlers for this input device
		printk(KERN_DEBUG "esm_register de-registering input device from (pid: %d)\n", task->pid);
                application = application_from_input_id(id, task);
		if(!input_id_equal(application->id, root_devices.id)){
			flush_workqueue(application->wq);	//<- call outside lock
			destroy_workqueue(application->wq);

			//Remove application from Global ESM application list
			spin_lock(&root_devices.lock);
			list_del(&application->list);
			kfree(application);
			spin_unlock(&root_devices.lock);
		} else {
			printk(KERN_ERR "esm_register could not de-register device: device ID not registered to the given application\n");
			return -1;
		}
	} else if (reg) {
		// Register input device to ESM
		printk(KERN_DEBUG "esm_register registering input device to (pid: %d)\n", task->pid);
		application = kmalloc(sizeof(application_l), GFP_KERNEL);
		if(!application){
			printk(KERN_ERR "esm_register could not kmalloc\n");
			return -ENOMEM;
		}
		if(copy_from_user(&epoll_e, epoll_item, sizeof(struct epoll_event)) < 0){
			printk(KERN_ERR "esm_register could not copy epoll item\n");
			return -1;
		}
		sprintf(wq_name,"%zu",(size_t)task->pid);
		wq = create_singlethread_workqueue(wq_name);	//<- call outside lock

		//Add application to Global ESM application list
		spin_lock(&root_devices.lock);
		application->task = task;
		application->id = id;
		application->wq = wq;
		application->ep_event = epoll_e;
		list_add(&(application->list), &(root_devices.list));
		spin_unlock(&root_devices.lock);
	}
	return 0;
}
int esm_register1(void __user* id, pid_t pid, void __user* ep_item, int reg) {
	return esm_register(id, pid, ep_item, reg);
}

/**
 * Dispatch event to application. Wakes up application in esm_wait, or queues event
 *
 * work: work_struct, container should be esm_work_data, which has
 *	esm_dispatch_args member, which has input_value and application_l* members
 */
void esm_dispatch(struct work_struct* work){
	struct event_queue_t* event_queue_item;
 	struct input_value* event;
	application_l* application;
	esm_work_data *work_data = container_of(work, esm_work_data, work);
	esm_dispatch_args data = work_data->data;
	application = data.application;
	printk(KERN_DEBUG "esm_dispatch is adding the registered event to event queue, pid: %d\n", application->task->pid);

	//Create copy of event into memory as to persist in the tasks' event_queues
	event = kmalloc(sizeof(struct input_value), GFP_KERNEL);
	if(!event){
		printk(KERN_ERR "esm_dispatch could not kmalloc\n");
		kfree(work_data);
		return;
	}
	memcpy(event, &data.event, sizeof(struct input_value));

	//Create event queue item that input event copy
	event_queue_item = kmalloc(sizeof(struct event_queue_t), GFP_KERNEL);
	if(!event_queue_item){
		printk(KERN_ERR "esm_dispatch could not kmalloc\n");
		kfree(work_data);
		return;
	}

	// Add event queue item to task's event queue
	spin_lock(&application->task->event_queue_lock);
	event_queue_item->event = event;
	event_queue_item->ep_event = application->ep_event;
	list_add_tail(&(event_queue_item->event_queue), &(application->task->event_queue.event_queue));
	spin_unlock(&application->task->event_queue_lock);

	// Attempt to wake up the process from esm_wait
	if(application->task->state == TASK_EV_WAIT){
		printk(KERN_DEBUG "esm_dispatch attempting to wake up process: %d\n", application->task->pid);
		if(wake_up_state(application->task, TASK_EV_WAIT) == 1){	//Less overhead to directly assign task->state = TASK_RUNNING
			printk(KERN_DEBUG "esm_dispatch: has waken up process %d; task now in state %ld\n", application->task->pid, application->task->state);
		}else{
			printk(KERN_DEBUG "esm_dispatch can not wake up process %d, already running\n", application->task->pid);
			kfree(work_data);
			return;
		}
	}

	kfree(work_data);
	return;
}

/**
 * Copy events to User space. This is the meat of esm_wait
 *
 * task: task that holds the event queue
 * event_buffer: user buffer to copy input events to
 * max_events: maximum number of events to copy to buffer
 *
 * Return: number of copied events or -EINVAL on failure
 */
int _handle_events(struct task_struct* task, void __user *event_buffer, int max_events, void __user *epoll_buffer){
	struct list_head *pos_one, *q;
	struct event_queue_t* ev_queue;
	struct input_value* event;
	struct epoll_event ep_event;
	int err = 0;
	int ret = 0;

	//Ensure the there are input events to report
	if(list_empty(&(task->event_queue.event_queue))){
		printk(KERN_ERR "No events to handle, pid: %d\n", task->pid);
		return -1;
	}

	//For each event in the task's event queue
	list_for_each_safe(pos_one, q, &(task->event_queue.event_queue)){
		printk(KERN_DEBUG "Handling events, pid: %d\n", task->pid);
		if(ret >= max_events){goto esm_out;}
		ev_queue = list_entry(pos_one, struct event_queue_t, event_queue);
		event = ev_queue->event;
		ep_event = ev_queue->ep_event;

		if(copy_to_user(event_buffer, event, sizeof(struct input_value)) || copy_to_user(epoll_buffer, &ep_event, sizeof(struct epoll_event))){
			printk(KERN_ERR "_handle_events: Failed to Copy Event to User Supplied Buffer\n");
			err = -EINVAL;
			goto esm_out;
		} else {
			ret += 1;
			event_buffer += sizeof(struct input_value);
			epoll_buffer += sizeof(struct epoll_event);
		}

		// Delete the Handled Event
		printk(KERN_DEBUG "Removing handled event from pid: %d\n", task->pid);
		spin_lock(&task->event_queue_lock);
		kfree(event);
		list_del(pos_one);
		kfree(ev_queue);
		spin_unlock(&task->event_queue_lock);
	}
esm_out:
	if(err < 0){ret = err;}
	return ret;
}

/**
 * Wait for registered events. Events are copied to user buffer. If there are events
 * already queued, then it does not sleep, otherwise it sleeps in state TASK_EV_WAIT
 *
 * event_buffer: user event buffer to recieve events (max: MAX_EVENTS)
 * max_events: maximum number of events to copy to buffer
 *
 * Return: number of events copied to user buffer
 */
int esm_wait(void __user *event_buffer, int max_events, void __user* epoll_buffer, pid_t pid){
	struct task_struct *task = find_task_by_vpid(pid);

	printk(KERN_DEBUG "esm_wait pid: %d\n", pid);
	// Schedule task if no waiting events
	if(list_empty(&(task->event_queue.event_queue))){
		printk(KERN_DEBUG "esm_wait: event_queue is empty, scheduling task\n");
		set_task_state(task, TASK_EV_WAIT);
		schedule();
	}

	return _handle_events(task, event_buffer, max_events, epoll_buffer);
}

int esm_wait1(void __user *event_buffer, int max_events, void __user* epoll_buffer, pid_t pid){
	return esm_wait(event_buffer, max_events, epoll_buffer, pid);
}

/**
 * Recieves input information from Evdev and sends to dispatch
 *
 * event: input value recieved
 * id: input device id that recieved the event
 *
 * Return: 0 on success, -1 on failure, -ENOMEM if no memory to allocate workqueue data
 */
int esm_interpret(struct input_value* event, struct input_id id){
	struct list_head *pos;
	application_l *app;
	static esm_dispatch_args dispatch_args;
	static esm_work_data* the_work_data;

	printk(KERN_DEBUG "Call to ESM Interpret\n");
	// Dispatch for each registered application handler
	if(!list_empty(&root_devices.list)){
		list_for_each(pos, &(root_devices.list)){
			app = list_entry(pos, application_l, list);
			if(input_id_equal(app->id, id)) {
				// Schedule work for esm_dispatch(event, app)
				dispatch_args.event = *event;
				dispatch_args.application = app;
				the_work_data = kmalloc(sizeof(esm_work_data), GFP_ATOMIC);
				if(the_work_data){
					the_work_data->data = dispatch_args;
					INIT_WORK(&the_work_data->work, esm_dispatch);
					queue_work(app->wq, &the_work_data->work);
				} else {
					printk(KERN_ERR "esm_interpret: Could not allocate work_queue data\n");
					return -ENOMEM;
				}
			}
		}
	}
	return 0;
}

/**
 * Changes state of the ESM system
 *
 * mode: if 0, moves all registered handlers and queued events from one task to another
 * pid1: process to move handlers from
 * pid2: process to move handlers to
 *
 * return 0 if success
 */
int esm_ctl(int mode, int pid1, int pid2) {
	struct task_struct* task;
	struct task_struct* task_new;
	application_l* app;
	struct list_head *pos, *pos_one, *q;
	struct event_queue_t* ev_queue;
	printk(KERN_DEBUG "Call to ESM_CTL: from pid: %d to pid: %d\n", pid1, current->pid);
	if (mode == 0) {
		if(!list_empty(&root_devices.list)){
			task = find_task_by_vpid(pid1);
			task_new = find_task_by_vpid(pid2);

			// Debug Statements
			print_debug_task_event_queue(task);
			print_debug_task_event_queue(task_new);

			// Transfer all registered handlers to new task
			list_for_each(pos, &(root_devices.list)){
				app = list_entry(pos, application_l, list);
				if (app->task == task) {
					app->task = task_new;
				}
			}

			// Transfer all queued events to new task
			if(!list_empty(&(task->event_queue.event_queue))){
				spin_lock(&task_new->event_queue_lock);
				list_for_each_safe(pos_one, q, &(task->event_queue.event_queue)){
					ev_queue = list_entry(pos_one, struct event_queue_t, event_queue);
					list_move(&(ev_queue->event_queue), &(task_new->event_queue.event_queue));
				}
				spin_unlock(&task_new->event_queue_lock);
			}

			// Debug Statement
			print_debug_task_event_queue(task_new);
		}
	}
	return 0;
}

int esm_ctl1(int mode, int pid1, int pid2) {
	return esm_ctl(mode, pid1, pid2);
}
