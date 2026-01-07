#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <chrono>
#include <iomanip>
#include <regex>
#include <filesystem>
#include <sstream>
#include <getopt.h>
#include <algorithm>

namespace beast = boost::beast;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace http = beast::http;

using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

struct URL {
    std::string scheme, host, port, path;
};

URL parse_url(const std::string& url) {
    std::regex url_regex("(https?)://([^/]+)(/.*)?");
    std::smatch match;
    if (!std::regex_match(url, match, url_regex)) {
        throw std::invalid_argument("invalid url format");
    }
    
    URL parsed_url;
    parsed_url.scheme = match[1].str();
    parsed_url.host = match[2].str();
    parsed_url.path = match[3].matched ? match[3].str() : "/";
    parsed_url.port = (parsed_url.scheme == "https") ? "443" : "80";
    
    return parsed_url;
}

void print_cert(ssl::stream<tcp::socket>& stream) {
    X509* cert = SSL_get_peer_certificate(stream.native_handle());
    if (!cert) return;

    char subj[512], iss[512];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));
    X509_NAME_oneline(X509_get_issuer_name(cert), iss, sizeof(iss));

    std::cout << "Server certificate:\n";
    std::cout << "  Subject: " << subj << "\n";
    std::cout << "  Issuer:  " << iss << "\n";

    X509_free(cert);
}

bool handle_request(const std::string& url, const std::string& outfile, std::string& redirect, std::size_t& body_size) {
    URL u = parse_url(url);
    asio::io_context io_context;
    tcp::resolver resolver(io_context);
    
    tcp::socket socket(io_context);
    auto endpoints = resolver.resolve(u.host, u.port);
    asio::connect(socket, endpoints);

    http::request<http::empty_body> req{http::verb::get, u.path, 11};
    req.set(http::field::host, u.host);
    req.set(http::field::user_agent, "mycurl");

    http::write(socket, req);
    beast::flat_buffer buffer;

    http::response<http::dynamic_body> res;
    http::read(socket, buffer, res);

    if (res.result() == http::status::moved_permanently || res.result() == http::status::found) {
        if (res.base().count(http::field::location)) {
            redirect = res.base()[http::field::location].to_string();
            return true;
        }
    }

    if (!outfile.empty()) {
        std::ofstream ofs(outfile, std::ios::binary);
        ofs << boost::beast::buffers_to_string(res.body().data());
    }

    body_size = res.body().size();
    return false;
}

void log_performance(std::size_t body_size, double duration) {
    double mbps = (body_size * 8.0) / (duration * 1e6);
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cout << std::put_time(std::localtime(&now), "%F %T") << " "
              << body_size << " bytes in " << std::fixed << std::setprecision(2) 
              << duration << " seconds (" << mbps << " Mbps)\n";
}

int main(int argc, char* argv[]) {
    try {
        std::string url;
        std::string output_file;
        
        static option long_options[] = {
            {"output", required_argument, nullptr, 'o'},
            {0, 0, 0, 0}
        };

        int c;
        while ((c = getopt_long(argc, argv, "o:", long_options, nullptr)) != -1) {
            if (c == 'o') {
                output_file = optarg;
            } else {
                std::cerr << "Error: unsupported option\n";
                return 1;
            }
        }

        if (optind >= argc) {
            std::cerr << "Error: URL is required!\n";
            return 1;
        }

        url = argv[optind];

        // Convert URL to lowercase for comparison
        std::transform(url.begin(), url.end(), url.begin(), ::tolower);

        if (url == "1") {
            std::cerr << "Error: Invalid URL format\n";
            return 1;
        }

        auto start_time = Clock::now();

        std::string redirect;
        int redirects = 0;
        std::size_t body_size = 0;

        while (true) {
            bool is_redirect = handle_request(url, output_file, redirect, body_size);
            if (!is_redirect) break;

            std::cout << "Redirecting to: " << redirect << "\n";
            url = redirect;

            if (++redirects > 10) {
                std::cerr << "Error: too many redirects\n";
                return 1;
            }
        }

        auto end_time = Clock::now();
        double elapsed_time = std::chrono::duration<double>(end_time - start_time).count();
        log_performance(body_size, elapsed_time);

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
