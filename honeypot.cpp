#include <iostream>
#include <fstream>
#include <cstring>
#include <ctime>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 22
#define LOG_FILE "honeypot_log.csv"

void scanOpenPorts(const char* ip) {
    std::cout << "Scanning open ports for IP: " << ip << std::endl;
    // Implement your port scanning logic here
    // You can use various techniques, such as connecting to different ports
    // and checking for successful connections or timeouts.
    // Note: Port scanning can be resource-intensive and may require appropriate permissions.
    // Be sure to comply with legal and ethical considerations.
    // For simplicity, we omit the port scanning implementation in this example.
}

void logConnection(const char* ip) {
    std::ofstream logfile(LOG_FILE, std::ios::app);
    if (!logfile) {
        std::cerr << "Error opening log file." << std::endl;
        return;
    }

    // Get current date and time
    std::time_t now = std::time(nullptr);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // Perform port scanning on the attacker's IP
    scanOpenPorts(ip);

    // Write the log entry to the CSV file
    logfile << ip << ",";
    // Modify the scanOpenPorts function to populate the open ports string accordingly
    std::string openPorts = ""; // Replace with the actual open ports separated by commas
    logfile << openPorts << ",";
    logfile << timestamp << std::endl;

    logfile.close();
}

int main() {
    int sockfd, client_sock;
    struct sockaddr_in server_addr, client_addr;
    char buffer[1024];

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket to server address
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(sockfd, 5) < 0) {
        perror("Error listening");
        exit(EXIT_FAILURE);
    }

    std::cout << "SSH honeypot is running on port " << PORT << "..." << std::endl;

    while (true) {
        socklen_t client_len = sizeof(client_addr);
        // Accept incoming connection
        client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);

        if (client_sock < 0) {
            perror("Error accepting connection");
            exit(EXIT_FAILURE);
        }

        // Log the attacker's IP address
        char* client_ip = inet_ntoa(client_addr.sin_addr);
        std::cout << "Connection from: " << client_ip << std::endl;

        // Log connection and open ports to CSV file
        logConnection(client_ip);

        // Send a fake SSH banner
        char* banner = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u2\r\n";
        send(client_sock, banner, strlen(banner), 0);

        // Read incoming data
        int num_bytes = recv(client_sock, buffer, sizeof(buffer), 0);

        // Process incoming data (optional)
        // Here, you can analyze the commands or authentication attempts made by the attacker
        // and log or record any relevant information.

        // Close the connection
        close(client_sock);
    }

    // Close the listening socket
    close(sockfd);

    return 0;
}
