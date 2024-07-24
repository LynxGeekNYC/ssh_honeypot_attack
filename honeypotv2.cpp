#include <libssh/libssh.h>
#include <libssh/server.h>
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <vector>

#define PORT 22
#define PASSWORD_DELAY 600 // 600 seconds (10 minutes)

using boost::asio::ip::tcp;

void delay(int seconds) {
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
}

std::string get_client_ip(ssh_session session) {
    return ssh_get_client_ip(session);
}

int authenticate_password(ssh_session session, std::ofstream& log_file) {
    ssh_message message;
    do {
        message = ssh_message_get(session);
        if (!message) {
            return SSH_MESSAGE_DISCONNECT;
        }
        if (ssh_message_type(message) == SSH_REQUEST_AUTH
            && ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
            std::string username = ssh_message_auth_user(message);
            std::string password = ssh_message_auth_password(message);
            log_file << "Attempted password: " << password << std::endl;
            std::cout << "Invalid password attempt: " << password << std::endl;
            ssh_message_auth_reply_default(message);
            ssh_message_free(message);
            delay(PASSWORD_DELAY); // Delay after each password attempt
            return SSH_AUTH_DENIED;
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    } while (true);
    return SSH_AUTH_ERROR;
}

std::vector<int> scan_ports(const std::string& ip) {
    boost::asio::io_context io_context;
    tcp::resolver resolver(io_context);
    tcp::resolver::query query(ip, "");
    tcp::resolver::iterator endpoints = resolver.resolve(query);
    std::vector<int> open_ports;

    for (int port = 1; port <= 65535; ++port) {
        tcp::socket socket(io_context);
        boost::system::error_code ec;
        socket.connect(tcp::endpoint(boost::asio::ip::address::from_string(ip), port), ec);
        if (!ec) {
            open_ports.push_back(port);
            socket.close();
        }
    }
    return open_ports;
}

int main() {
    ssh_session session;
    ssh_bind sshbind;
    int auth = 0;
    int rc;

    std::ofstream log_file("honeypot_log.txt", std::ios::app);

    sshbind = ssh_bind_new();
    if (sshbind == nullptr) {
        std::cerr << "Error creating SSH bind." << std::endl;
        return 1;
    }

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "ssh_host_rsa_key");

    rc = ssh_bind_listen(sshbind);
    if (rc < 0) {
        std::cerr << "Error listening to socket: " << ssh_get_error(sshbind) << std::endl;
        ssh_bind_free(sshbind);
        return 1;
    }

    session = ssh_new();
    if (session == nullptr) {
        std::cerr << "Error creating SSH session." << std::endl;
        ssh_bind_free(sshbind);
        return 1;
    }

    rc = ssh_bind_accept(sshbind, session);
    if (rc == SSH_ERROR) {
        std::cerr << "Error accepting connection: " << ssh_get_error(sshbind) << std::endl;
        ssh_free(session);
        ssh_bind_free(sshbind);
        return 1;
    }

    rc = ssh_handle_key_exchange(session);
    if (rc != SSH_OK) {
        std::cerr << "Error handling key exchange: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        ssh_bind_free(sshbind);
        return 1;
    }

    std::string client_ip = get_client_ip(session);
    log_file << "Connection from IP: " << client_ip << std::endl;
    std::cout << "Connection from IP: " << client_ip << std::endl;

    auth = authenticate_password(session, log_file);
    if (auth != SSH_AUTH_SUCCESS) {
        std::cerr << "Authentication failed" << std::endl;
    }

    log_file << "Scanning ports for IP: " << client_ip << std::endl;
    std::vector<int> open_ports = scan_ports(client_ip);
    log_file << "Open ports: ";
    for (int port : open_ports) {
        log_file << port << " ";
    }
    log_file << std::endl;

    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);
    log_file.close();

    return 0;
}
