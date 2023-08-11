// Copyright (C) 2021-2023, HardenedVault Limited (https://hardenedvault.net)

#define WCFI_STACK_EVENT 0
#define WCFI_RETURN_EVENT 1
#define WCFI_SP_EVENT 2

#define PSD_UPDATE_EVENT 3
#define PSD_CHECK_EVENT 4
#define PSD_DELETE_EVENT 5

class event {
    byte type;
    int pid;
#define ED_TASK_COMM_LEN 0x20
    char[ED_TASK_COMM_LEN] name;
    unsigned long ip;
    unsigned long time;

    byte type(void);
    bool is_wcfi_stack_event() {return type == WCFI_STACK_EVENT;}
    bool is_wcfi_return_event() {return type == WCFI_RETURN_EVENT;}
    bool is_wcfi_sp_event() {return type == WCFI_SP_EVENT;}
    bool is_psd_update_event() {return type == PSD_UPDATE_EVENT;}
    bool is_psd_check_event() {return type == PSD_CHECK_EVENT;}
    bool is_psd_delete_event() {return type == PSD_DELETE_EVENT;}

    std::string basic_event_info();
};

class wcfi_stack_event : event {
    int kstack_id;

    std::string info_string(BPFExploitDetect bpf_ed);
};

class wcfi_return_event : event {
    unsigned long func_ip;
    unsigned long ret_addr;
};

class wcfi_sp_event : event {
    unsigned long current_sp;
    unsigned long reg_sp;
    unsigned long stack_size;
};

class psd_event : event {
    unsigned cred_hash;
    unsigned spacename_hash;
    unsigned long cred_p;
};
