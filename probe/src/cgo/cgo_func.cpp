//
// Created by jundi zhou on 2022/6/1.
//

#include "cgo_func.h"
#include "kindling.h"


int runForGo(){
	return init_probe();
}

int getKindlingEvent(void **kindlingEvent){
	return getEvent(kindlingEvent);
}


void subEventForGo(char* eventName, char* category){
	sub_event(eventName, category);
}

int startProfile() {
    return start_profile();
}
int stopProfile() {
    return stop_profile();
}

void updateCameraMonitorWhitelistForGo(unsigned long pid, int isAdd, unsigned long ts){
    update_camera_monitor_whitelist(int64_t(pid), isAdd, int64_t(ts));
}

void removeWhiteListForGo(){
    removeWhiteList();
}