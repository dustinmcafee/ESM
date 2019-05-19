#ifndef _ESM_H
#define _ESM_H
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
#include <linux/workqueue.h>
#include <linux/eventpoll.h>

typedef struct {
	spinlock_t lock;
	struct list_head list;
	struct task_struct* task;
	struct workqueue_struct *wq;
	struct input_id id;
	struct epoll_event ep_event;
}application_l;

typedef struct {
	struct input_value event;
	application_l* application;
}esm_dispatch_args;

typedef struct {
	struct work_struct work;
	esm_dispatch_args data;
}esm_work_data;

application_l* application_from_input_id(struct input_id id, struct task_struct* task);

/**
 * Register ESM to process (pid)
 * id: input device to register/deregister
 * pid: process to register/deregister to/from
 * reg: 1 to register, 0 to deregister
 *
 * Return: 0 on success, -1 on failure
 */
int esm_register(void __user* id, pid_t pid, void __user* ep_item, int reg);
int esm_register1(void __user* id, pid_t pid, void __user* ep_item, int reg);

/**
 * Dispatch event to application. Wakes up application in esm_wait, or queues event
 *
 * event: input event to dispatch
 * application: task to dispatch to
 *
 * Return 0 on Success, -1 on Failure
 */
//int esm_dispatch(struct input_value event, application_l* application);
void esm_dispatch(struct work_struct *work);

/**
 * Wait for registered events. Events are copied to user buffer. If there are events
 * already queued, then it does not sleep, otherwise it sleeps in state TASK_EV_WAIT
 *
 * event_buffer: user event buffer to recieve events (max: MAX_EVENTS)
 * max_events: maximum number of events to copy to buffer
 *
 * Return: number of events copied to user buffer
 */
int esm_wait(void __user *event_buffer, int max_events, void __user* ep_buffer, pid_t pid);
int esm_wait1(void __user *event_buffer, int max_events, void __user* ep_buffer, pid_t pid);

/**
 * Recieves input information from Evdev and sends to dispatch
 *
 * ev: input value recieved
 * id: input device id that recieved the event
 *
 * Return: 0 on success, -1 on failure
 */
int esm_interpret(struct input_value* event, struct input_id);

int esm_ctl(int mode, int arg1, int arg2);

#endif	//_ESM_H
