#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <pthread.h> 
#include <semaphore.h>
#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>

// States associated with different I/O operations related to HTTP proxy operations
#define READ_REQUEST 1
#define SEND_REQUEST 2
#define READ_RESPONSE 3
#define SEND_RESPONSE 4

#define MAX_OBJECT_SIZE 102400 

static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:97.0) Gecko/20100101 Firefox/97.0";

struct request_info { 
    int client_socket;         // client-to-proxy socket
    int server_socket;         // proxy-to-server socket
    int state;                 // current state of the request

    char buffer[MAX_OBJECT_SIZE];  // buffer to read into and write from
    
    size_t total_bytes_read_from_client;
    size_t total_bytes_to_write_to_server;
    size_t total_bytes_written_to_server;
    size_t total_bytes_read_from_server;
    size_t total_bytes_written_to_client;
};

int complete_request_received(char *);
int parse_request(char *, char *, char *, char *, char *);
void test_parser();
void print_bytes(unsigned char *, int);
int open_sfd(int);
void handle_new_clients(int, int);
void handle_client(struct request_info* client_request, int); 

int main(int argc, char *argv[]) { 
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port_number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);

    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    // Create and open the listening socket
    int listen_sfd = open_sfd(port);

    // Register the listening socket with epoll for reading and edge-triggered monitoring
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;  
    event.data.fd = listen_sfd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_sfd, &event) == -1) {
        perror("EPOLL CTL");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Call epoll_wait with a timeout of 1 second
        struct epoll_event events[10];  // Adjust the size based on your requirements
        int num_events = epoll_wait(epoll_fd, events, 10, 1000);  // 1 second timeout

        if (num_events < 0) {
            perror("EPOLL WAIT");
            exit(EXIT_FAILURE);
        }

        // Loop through all events and handle each appropriately
        for (int i = 0; i < num_events; i++) {
            if (events[i].data.fd == listen_sfd) {
                // Event corresponds to the listening socket, handle new clients
                handle_new_clients(epoll_fd, listen_sfd);
            } else { 
                struct request_info *current_request = (struct request_info *)events[i].data.ptr; 
                handle_client(current_request, epoll_fd); 
            }
        }
    }

    // Cleanup resources (free malloc'd memory, close sockets, etc.)
    close(listen_sfd);
    close(epoll_fd);

    return 0;
}

int complete_request_received(char *request) {
	// Use strstr to find the end-of-headers sequence "\r\n\r\n"
    // If the sequence is found, the request is complete  
    return (strstr(request, "\r\n\r\n") != NULL) ? 1 : 0;
}

int parse_request(char *request, char *method, char *hostname, char *port, char *path) {
    // Extract method
    char *beginning = request;

    // Space indicates end of method
    char *end = strstr(beginning, " ");
    
	// Copy method
    strncpy(method, beginning, end - beginning);
    method[end - beginning] = '\0';

    // Move beyond the first space to start of the URL
    beginning = end + 1;

    // Extract URL
    // Find next space
    end = strstr(beginning, " ");
    char url[1024];                      
    strncpy(url, beginning, end - beginning);
    url[end - beginning] = '\0';

    char *url_beginning = strstr(url, "://");
    if (!url_beginning) return 0;  
    url_beginning += 3;  

    // Extract hostname, port, and path from the URL
    char *colon_position = strstr(url_beginning, ":");
    char *slash_position = strstr(url_beginning, "/");
    
    // Check if a colon is present in the URL after "://" and if there is a slash after the colon
    if (colon_position != NULL && slash_position && colon_position < slash_position) {
        // Extract and copy the hostname from the URL
        strncpy(hostname, url_beginning, colon_position - url_beginning);
        hostname[colon_position - url_beginning] = '\0'; 
        
        // Extract and copy the port from the URL
        strncpy(port, colon_position + 1, slash_position - (colon_position + 1));
        port[slash_position - (colon_position + 1)] = '\0'; 
    } else {
        // If no colon or the colon is after the slash, use default port 80
        // Extract and copy the hostname from the URL
        strncpy(hostname, url_beginning, slash_position - url_beginning);
        hostname[slash_position - url_beginning] = '\0'; 

        // Set the port to the default value "80"
        strcpy(port, "80");
    }

    // Copy the path from the URL (including the leading "/")
    strcpy(path, slash_position);

    // Check if the entire request has been received
    return complete_request_received(request);
}

void test_parser() {
	int i;
	char method[16], hostname[64], port[8], path[64];

       	char *reqs[] = {
		"GET http://www.example.com/index.html HTTP/1.0\r\n"
		"Host: www.example.com\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html?foo=1&bar=2 HTTP/1.0\r\n"
		"Host: www.example.com:8080\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://localhost:1234/home.html HTTP/1.0\r\n"
		"Host: localhost:1234\r\n"
		"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\n"
		"Accept-Language: en-US,en;q=0.5\r\n\r\n",

		"GET http://www.example.com:8080/index.html HTTP/1.0\r\n",

		NULL
	};
	
	for (i = 0; reqs[i] != NULL; i++) {
		printf("Testing %s\n", reqs[i]);
		if (parse_request(reqs[i], method, hostname, port, path)) {
			printf("METHOD: %s\n", method);
			printf("HOSTNAME: %s\n", hostname);
			printf("PORT: %s\n", port);
			printf("PATH: %s\n", path);
		} else {
			printf("REQUEST INCOMPLETE\n");
		}
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

int open_sfd(int port) {
    // Create a TCP socket
    int sfd;
    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Allow the socket to bind to an address and port already in use
    int optval = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) == -1) {
        perror("Error setting socket options");
        close(sfd);
        exit(EXIT_FAILURE);
    }

	// Configure the socket for non-blocking I/O
	if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL, 0) | O_NONBLOCK) < 0) {
		fprintf(stderr, "error setting socket option\n");
        exit(EXIT_FAILURE);
    }

    // Configure the server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr)); 
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind the socket to the specified port
    if (bind(sfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        close(sfd);
        exit(EXIT_FAILURE);
    }

    // Configure the socket for accepting new clients
    if (listen(sfd, SOMAXCONN) == -1) {
        perror("Error listening on socket");
        close(sfd);
        exit(EXIT_FAILURE);
    }

    return sfd;
}

void handle_new_clients(int epoll_fd, int listen_sfd) {
    while (1) {
        // Accept new clients
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sfd = accept(listen_sfd, (struct sockaddr*)&client_addr, &client_len);

        if (client_sfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No more clients pending
                break;
            } else {
                perror("accept");
                exit(EXIT_FAILURE);
            }
        }

        // Configure the client socket for non-blocking I/O
        int flags = fcntl(client_sfd, F_GETFL, 0);
        if (flags == -1) {
            perror("fcntl");
            exit(EXIT_FAILURE);
        }
        if (fcntl(client_sfd, F_SETFL, flags | O_NONBLOCK) == -1) {
            perror("fcntl");
            exit(EXIT_FAILURE);
        }

        // Allocate memory for request_info struct
        struct request_info *request_info = (struct request_info*)malloc(sizeof(struct request_info));
        if (!request_info) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        // Initialize request_info values
        request_info->client_socket = client_sfd;
        request_info->server_socket = -1;  // Initialize to an invalid value
        request_info->state = READ_REQUEST;
        request_info->total_bytes_read_from_client = 0;
        request_info->total_bytes_to_write_to_server = 0;
        request_info->total_bytes_written_to_server = 0;
        request_info->total_bytes_read_from_server = 0;
        request_info->total_bytes_written_to_client = 0;

        // Register the client socket with epoll for reading
        struct epoll_event event;
        event.events = EPOLLIN | EPOLLET;  // Edge-triggered monitoring
        event.data.ptr = request_info;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sfd, &event) == -1) {
            perror("epoll_ctl");
            exit(EXIT_FAILURE);
        }

        printf("New client connected. File descriptor: %d\n", client_sfd);
    }
}

void handle_client(struct request_info *client_request, int epoll_fd) {
    printf("Handling client with file descriptor %d in state %d\n", client_request->client_socket, client_request->state);

    int client_socket = client_request->client_socket;
    int server_socket = client_request->server_socket;
    int state = client_request->state;

    printf("Client File Descriptor: %d, Current State: %d\n", client_socket, state);

    switch (state) {
        case READ_REQUEST: {
            printf("Read Request\n");
            while (1) {
                ssize_t bytes_read = read(client_socket, client_request->buffer + client_request->total_bytes_read_from_client, MAX_OBJECT_SIZE - client_request->total_bytes_read_from_client);

                if (bytes_read > 0) {
                    client_request->total_bytes_read_from_client += bytes_read;

                    // Check if the entire HTTP request has been read
                    if (complete_request_received(client_request->buffer)) {
                        // Print the HTTP request using print_bytes()
                        printf("Received HTTP Request:\n");
                        print_bytes((unsigned char *)client_request->buffer, client_request->total_bytes_read_from_client);

                        // Add a null-terminator to the HTTP request
                        client_request->buffer[client_request->total_bytes_read_from_client] = '\0';

                        // Parse the HTTP request
                        char method[16], hostname[64], port[8], path[64];

                        if (parse_request(client_request->buffer, method, hostname, port, path)) {
                            // Print components of the HTTP request
                            printf("Method: %s\n", method);
                            printf("Hostname: %s\n", hostname);
                            printf("Port: %s\n", port);
                            printf("Path: %s\n", path);

                            // Create the request to send to the server                            
                            snprintf(client_request->buffer, MAX_OBJECT_SIZE, "%s %s HTTP/1.0\r\n" "Host: %s:%s\r\n" "%s\r\n\r\n", method, path, hostname, port, user_agent_hdr);
                            client_request->total_bytes_to_write_to_server = strlen(client_request->buffer);  

                            // Use print_bytes() to print out the HTTP request to be sent
                            print_bytes((unsigned char *)client_request->buffer, strlen(client_request->buffer));

                            int server_socket = socket(AF_INET, SOCK_STREAM, 0);
                            if (server_socket == -1) {
                                perror("socket");
                                exit(EXIT_FAILURE);
                            }

                            struct sockaddr_in server_addr;
                            memset(&server_addr, 0, sizeof(server_addr));
                            server_addr.sin_family = AF_INET;
                            server_addr.sin_port = htons(atoi(port));

                            struct hostent *host = gethostbyname(hostname);
                            if (!host) {
                                perror("gethostbyname");
                                close(server_socket);
                                exit(EXIT_FAILURE);
                            }
                            memcpy(&server_addr.sin_addr, host->h_addr, host->h_length);

                            // Configure the new socket as nonblocking
                            if (fcntl(server_socket, F_SETFL, fcntl(server_socket, F_GETFL, 0) | O_NONBLOCK) < 0) {
                                perror("fcntl");
                                close(server_socket);
                                exit(EXIT_FAILURE);
                            }

                            if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                                if (errno != EINPROGRESS) {
                                    perror("connect");
                                    close(server_socket);
                                    exit(EXIT_FAILURE);
                                }
                            }

                            // Save the server socket in the request_info struct
                            client_request->server_socket = server_socket;

                            // Unregister the client-to-proxy socket from epoll
                            struct epoll_event event;
                            event.events = 0;   
                            event.data.ptr = NULL;

                            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_socket, &event) == -1) {
                                perror("epoll_ctl");
                                exit(EXIT_FAILURE);
                            }

                            event.events = EPOLLOUT | EPOLLET;   
                            event.data.ptr = client_request;

                            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_request->server_socket, &event) == -1) {
                                perror("epoll_ctl");
                                exit(EXIT_FAILURE);
                            } 

                            client_request->state = SEND_REQUEST;
                            printf("%ld", bytes_read);
                        }
                    }
                } else if (bytes_read == 0) { 
                    close(client_socket);
                    free(client_request);
                    return;
                } else {
                    // Error reading from the socket
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return;
                    } else {
                        perror("Read");
                        close(client_socket);
                        free(client_request);
                        return;
                    }
                }
            }
            break;
        }
        case SEND_REQUEST: { 
            while (1) {
                ssize_t bytes_sent = write(server_socket,client_request->buffer + client_request->total_bytes_written_to_server, client_request->total_bytes_to_write_to_server - client_request->total_bytes_written_to_server);
                printf("%ld", bytes_sent);

                if (bytes_sent > 0) {
                    client_request->total_bytes_written_to_server += bytes_sent;

                    // Check if the entire HTTP request has been sent
                    if (client_request->total_bytes_written_to_server == client_request->total_bytes_to_write_to_server) {
                        // Unregister the proxy-to-server socket with epoll for writing
                        struct epoll_event event;
                        event.events = 0;  // No events        
                        event.data.ptr = NULL;

                        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server_socket, &event) == -1) {
                            perror("epoll_ctl");
                            exit(EXIT_FAILURE);
                        }

                        // Register the proxy-to-server socket with epoll for reading
                        event.events = EPOLLIN | EPOLLET;   
                        event.data.ptr = client_request;

                        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_socket, &event) == -1) {
                            perror("epoll_ctl");
                            exit(EXIT_FAILURE);
                        } 

                        client_request->state = READ_RESPONSE;
                        return;  
                    }
                } else if (bytes_sent == 0) { 
                    printf("Warning: write() returned 0 bytes\n");
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return;
                    } else {
                        perror("Write");
                        close(client_socket);
                        close(server_socket);
                        free(client_request);
                        return;
                    }
                }
            }
            break;
        }
    case READ_RESPONSE: {
    while (1) {
        ssize_t bytes_received = read(server_socket,client_request->buffer + client_request->total_bytes_read_from_server, MAX_OBJECT_SIZE - client_request->total_bytes_read_from_server);

        if (bytes_received > 0) {
            printf("Received chunk of %zd bytes from server\n", bytes_received);
            client_request->total_bytes_read_from_server += bytes_received;
        } else if (bytes_received == 0) {
            printf("Full response received from server. Total bytes: %zu\n", client_request->total_bytes_read_from_server);
            printf("Received HTTP Response:\n");
            print_bytes((unsigned char *)client_request->buffer, client_request->total_bytes_read_from_server);
            
            // Register the client-to-proxy socket with epoll for writing
            struct epoll_event event;
            event.events = EPOLLOUT | EPOLLET; 
            event.data.ptr = client_request;
            
            if (fcntl(client_socket, F_GETFL) == -1) {
                perror("fcntl - client_socket check");
            }

            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_socket, &event) == -1) {
                perror("epoll_ctl");
                exit(EXIT_FAILURE);
            }

            client_request->state = SEND_RESPONSE;

            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, server_socket, NULL) == -1) {
                perror("epoll_ctl - DELETE server_socket");
            }
            close(server_socket);

            return; 
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                perror("Read");
                close(client_socket);
                close(server_socket);
                free(client_request);
                return;
            }
        }
    }
    break;
}
case SEND_RESPONSE: {
    // Loop to write the response to the client-to-proxy socket
    while (1) {
        ssize_t bytes_sent = write(client_socket, client_request->buffer + client_request->total_bytes_written_to_client, client_request->total_bytes_read_from_server - client_request->total_bytes_written_to_client);
        if (bytes_sent > 0) {
            printf("Sent chunk of %zd bytes to client\n", bytes_sent);
            client_request->total_bytes_written_to_client += bytes_sent;

            
            if (client_request->total_bytes_written_to_client == client_request->total_bytes_read_from_server) {
                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_socket, NULL) == -1) {
                    perror("epoll_ctl - DELETE client_socket");
                }

                free(client_request);
                close(client_socket);
                return; 
            }
        } else if (bytes_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            } else {
                perror("write");
                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_socket, NULL) == -1) {
                    perror("epoll_ctl - DELETE client_socket");
                }
                close(client_socket);
                free(client_request);
                return;
            }
        } else {
            perror("Write");
            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_socket, NULL) == -1) {
                perror("epoll_ctl - DELETE client_socket");
            }
            close(client_socket);
            free(client_request);
            return;
        }
    }
    break;
}
    default: 
        fprintf(stderr, "Invalid state: %d\n", state);
        break;
    }
}