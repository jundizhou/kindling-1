//
// Created by jundi on 2023/2/24.
//

#include "java_info_parser.h"
#include "sinsp.h"

char* traceId = new char[128];
char* isEnter = new char[16];
char* protocol = new char[32];
char* url = new char[256];
char* start_time_char = new char[32];
char* end_time_char = new char[32];
char* tid_char = new char[32];
char* time_char = new char[32];
char* depth_char = new char[8];
char* finish_char = new char[4];
char* kd_stack = new char[1024];
char* duration_char = new char[32];
char* span_char = new char[1024];

void parse_jf(char* data_val, sinsp_evt_param data_param, kindling_event_t_for_go* p_kindling_event,
              sinsp_threadinfo* threadInfo, uint16_t& userAttNumber) {
  int val_offset = 0;
  int tmp_offset = 0;
  for (int i = 6; i < data_param.m_len; i++) {
    if (data_val[i] == '!') {
      if (val_offset == 0) {
        start_time_char[tmp_offset] = '\0';
      } else if (val_offset == 1) {
        end_time_char[tmp_offset] = '\0';
      } else if (val_offset == 2) {
        tid_char[tmp_offset] = '\0';
        break;
      }
      tmp_offset = 0;
      val_offset++;
      continue;
    }
    if (val_offset == 0) {
      start_time_char[tmp_offset] = data_val[i];
    } else if (val_offset == 1) {
      end_time_char[tmp_offset] = data_val[i];
    } else if (val_offset == 2) {
      tid_char[tmp_offset] = data_val[i];
    }
    tmp_offset++;
  }
  p_kindling_event->timestamp = atol(start_time_char);
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "end_time");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value,
         to_string(atol(end_time_char)).data(), 19);
  p_kindling_event->userAttributes[userAttNumber].valueType = UINT64;
  p_kindling_event->userAttributes[userAttNumber].len = 19;
  userAttNumber++;
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "data");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, data_val, data_param.m_len);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = data_param.m_len;
  userAttNumber++;
  strcpy(p_kindling_event->name, "java_futex_info");
  p_kindling_event->context.tinfo.tid = threadInfo->m_tid;
  map<uint64_t, char*>::iterator key =
      ptid_comm.find(threadInfo->m_pid << 32 | (threadInfo->m_tid & 0xFFFFFFFF));
  if (key != ptid_comm.end()) {
    strcpy(p_kindling_event->context.tinfo.comm, key->second);
  } else {
    strcpy(p_kindling_event->context.tinfo.comm, (char*)threadInfo->m_comm.data());
  }
  p_kindling_event->context.tinfo.pid = threadInfo->m_pid;
  p_kindling_event->paramsNumber = userAttNumber;
}

void parse_xtid(sinsp_evt* s_evt, char* data_val, sinsp_evt_param data_param,
                kindling_event_t_for_go* p_kindling_event, sinsp_threadinfo* threadInfo,
                uint16_t& userAttNumber) {
  int val_offset = 0;
  int tmp_offset = 0;
  int traceId_offset = 0;
  int protocol_offset = 0;
  int url_offset = 0;
  for (int i = 8; i < data_param.m_len; i++) {
    if (data_val[i] == '!') {
      if (val_offset == 0) {
        traceId[tmp_offset] = '\0';
        traceId_offset = tmp_offset;
      } else if (val_offset == 1) {
        isEnter[tmp_offset] = '\0';
      } else if (val_offset == 2) {
        protocol[tmp_offset] = '\0';
        protocol_offset = tmp_offset;
      } else if (val_offset == 3) {
        url[tmp_offset] = '\0';
        url_offset = tmp_offset;
        break;
      }
      tmp_offset = 0;
      val_offset++;
      continue;
    }
    if (val_offset == 0) {
      traceId[tmp_offset] = data_val[i];
    } else if (val_offset == 1) {
      isEnter[tmp_offset] = data_val[i];
    } else if (val_offset == 2) {
      protocol[tmp_offset] = data_val[i];
    } else if (val_offset == 3) {
      url[tmp_offset] = data_val[i];
    }

    tmp_offset++;
  }
  p_kindling_event->timestamp = s_evt->get_ts();
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "trace_id");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, traceId, traceId_offset);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = traId_offset;
  userAttNumber++;ce
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "is_enter");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, isEnter, 1);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = 1;
  userAttNumber++;
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "protocol");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, protocol, protocol_offset);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = protocol_offset;
  userAttNumber++;
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "url");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, url, url_offset);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = url_offset;
  userAttNumber++;
  strcpy(p_kindling_event->name, "apm_trace_id_event");
  p_kindling_event->context.tinfo.tid = threadInfo->m_tid;
  map<uint64_t, char*>::iterator key =
      ptid_comm.find(threadInfo->m_pid << 32 | (threadInfo->m_tid & 0xFFFFFFFF));
  if (key != ptid_comm.end()) {
    strcpy(p_kindling_event->context.tinfo.comm, key->second);
  } else {
    strcpy(p_kindling_event->context.tinfo.comm, (char*)threadInfo->m_comm.data());
  }
  p_kindling_event->context.tinfo.pid = threadInfo->m_pid;
  strcpy(p_kindling_event->context.tinfo.containerId, (char*)threadInfo->m_container_id.data());
  p_kindling_event->paramsNumber = userAttNumber;
}

void parse_span(sinsp_evt* s_evt, char* data_val, sinsp_evt_param data_param,
                kindling_event_t_for_go* p_kindling_event, sinsp_threadinfo* threadInfo,
                uint16_t& userAttNumber) {
  if (data_param.m_len < 10) {
    return;
  }
  int val_offset = 0;
  int tmp_offset = 0;
  int span_offset = 0;
  int traceId_offset = 0;

  bool version_new = false;
  int fromIndex = 8;
  if (data_val[8] == '1' && data_val[9] == '!') {
    version_new = true;
    fromIndex = 10;
  }
  for (int i = fromIndex; i < data_param.m_len; i++) {
    if (data_val[i] == '!') {
      if (val_offset == 0) {
        duration_char[tmp_offset] = '\0';
      } else if (val_offset == 1) {
        span_char[tmp_offset] = '\0';
        span_offset = tmp_offset;
      } else if (val_offset == 2) {
        traceId[tmp_offset] = '\0';
        traceId_offset = tmp_offset;
        break;
      }
      tmp_offset = 0;
      val_offset++;
      continue;
    }
    if (val_offset == 0) {
      duration_char[tmp_offset] = data_val[i];
    } else if (val_offset == 1) {
      span_char[tmp_offset] = data_val[i];
    } else if (val_offset == 2) {
      traceId[tmp_offset] = data_val[i];
    }
    tmp_offset++;
  }
  if (version_new) {
    // StartTime
    p_kindling_event->timestamp = atol(duration_char);
  } else {
    // EndTime - Duration
    p_kindling_event->timestamp = s_evt->get_ts() - atol(duration_char);
  }
  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "end_time");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, to_string(s_evt->get_ts()).data(),
         19);
  p_kindling_event->userAttributes[userAttNumber].valueType = UINT64;
  p_kindling_event->userAttributes[userAttNumber].len = 19;
  userAttNumber++;

  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "trace_id");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, traceId, traceId_offset);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = traceId_offset;
  userAttNumber++;

  strcpy(p_kindling_event->userAttributes[userAttNumber].key, "span");
  memcpy(p_kindling_event->userAttributes[userAttNumber].value, span_char, span_offset);
  p_kindling_event->userAttributes[userAttNumber].valueType = CHARBUF;
  p_kindling_event->userAttributes[userAttNumber].len = span_offset;
  userAttNumber++;

  strcpy(p_kindling_event->name, "apm_span_event");
  p_kindling_event->context.tinfo.tid = threadInfo->m_tid;
  map<uint64_t, char*>::iterator key =
      ptid_comm.find(threadInfo->m_pid << 32 | (threadInfo->m_tid & 0xFFFFFFFF));
  if (key != ptid_comm.end()) {
    strcpy(p_kindling_event->context.tinfo.comm, key->second);
  }
  p_kindling_event->context.tinfo.pid = threadInfo->m_pid;
  p_kindling_event->paramsNumber = userAttNumber;
}

void parse_tm(char* data_val, sinsp_evt_param data_param, sinsp_threadinfo* threadInfo) {
  char* comm_char = new char[256];
  int val_offset = 0;
  int tmp_offset = 0;
  for (int i = 6; i < data_param.m_len; i++) {
    if (data_val[i] == '!') {
      if (val_offset == 0) {
        tid_char[tmp_offset] = '\0';
      } else if (val_offset == 1) {
        comm_char[tmp_offset] = '\0';
        break;
      }
      tmp_offset = 0;
      val_offset++;
      continue;
    }
    if (val_offset == 0) {
      tid_char[tmp_offset] = data_val[i];
    } else if (val_offset == 1) {
      comm_char[tmp_offset] = data_val[i];
    }
    tmp_offset++;
  }
  uint64_t v_tid = inspector->get_pid_vtid_info(threadInfo->m_pid, atol(tid_char));
  if (v_tid == 0) {
    if (ptid_comm[threadInfo->m_pid << 32 | (atol(tid_char) & 0xFFFFFFFF)] != nullptr &&
        memcmp(ptid_comm[threadInfo->m_pid << 32 | (atol(tid_char) & 0xFFFFFFFF)], comm_char,
               strlen(comm_char)) == 0) {
      delete[] comm_char;
    } else {
      ptid_comm[threadInfo->m_pid << 32 | (atol(tid_char) & 0xFFFFFFFF)] = comm_char;
    }
  } else {
    if (ptid_comm[threadInfo->m_pid << 32 | (v_tid & 0xFFFFFFFF)] != nullptr &&
        memcmp(ptid_comm[threadInfo->m_pid << 32 | (v_tid & 0xFFFFFFFF)], comm_char,
               strlen(comm_char)) == 0) {
      delete[] comm_char;
    } else {
      ptid_comm[threadInfo->m_pid << 32 | (v_tid & 0xFFFFFFFF)] = comm_char;
    }
  }
}
