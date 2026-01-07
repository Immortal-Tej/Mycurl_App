#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <iomanip>
#include <regex>
#include <set>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

// Struct to store URL components
struct Url {
    std::string scheme, host, port, path;
};

// Parse the URL into scheme, host, port, and path
Url parse_url(const std::string& url) {
    std::regex url_regex("(https?)://([^/]+)(/.*)?");
    std::smatch match;
    if (!std::regex_match(url, match, url_regex)) {
        throw std::invalid_argument("Invalid URL format");
    }

    Url parsed_url;
    parsed_url.scheme = match[1].str();
    parsed_url.host = match[2].str();
    parsed_url.path = match[3].matched ? match[3].str() : "/";

    // Default ports for HTTP and HTTPS
    parsed_url.port = (parsed_url.scheme == "https") ? "443" : "80";

    return parsed_url;
}

// Print response details
void print_response(const http::response<http::dynamic_body>& res) {
    std::cout << "Response Status: " << res.result() << "\n";
    for (const auto& header : res.base()) {
        std::cout << header.name_string() << ": " << header.value() << "\n";
    }
}

// Save response to file
void save_response(const http::response<http::dynamic_body>& res, const std::string& outfile) {
    if (!outfile.empty()) {
        std::ofstream ofs(outfile, std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("Failed to open output file");
        }
        ofs << boost::beast::buffers_to_string(res.body().data());
        ofs.close();
    }
}

// Handle HTTP redirects with a limit of 10
std::string handle_redirect(http::response<http::dynamic_body>& res, const std::string& url, std::string& redirect_url, size_t& redirects, std::set<std::string>& visited_urls) {
    if (res.result_int() >= 300 && res.result_int() < 400 && res.base().count(http::field::location)) {
        redirect_url = res.base()[http::field::location].to_string();

        // Check if the redirect URL is the same as the current one or has already been visited
        if (visited_urls.find(redirect_url) != visited_urls.end() || redirect_url == url) {
            std::cout << "Redirect loop detected, stopping...\n";
            return "";  // Return empty to stop redirects
        }

        std::cout << "Redirecting to: " << redirect_url << "\n";
        visited_urls.insert(redirect_url);  // Mark this URL as visited
        ++redirects;
        if (redirects > 10) {
            std::cerr << "Error: Too many redirects\n";
            return "";  // Stop after 10 redirects
        }
        return redirect_url;  // Return the new URL for the next redirection
    }
    return "";  // No redirection
}

// Perform the HTTP(S) request and handle the response
void get_url(std::string& url, const std::string& output_file) {
    try {
        // Parse the URL into components
        Url parsed_url = parse_url(url);

        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);

        // Resolve the host
        auto results = resolver.resolve(parsed_url.host, parsed_url.port);

        // Initialize response variables
        std::string redirect_url;
        size_t redirects = 0;
        size_t body_size = 0;

        // Track visited URLs to avoid redirects loop
        std::set<std::string> visited_urls;
        visited_urls.insert(url);

        while (true) {
            // Make HTTP(S) request based on the scheme
            if (parsed_url.scheme == "https") {
                ssl::context ssl_context(ssl::context::tls_client);
                ssl::stream<tcp::socket> ssl_stream(io_context, ssl_context);
                asio::connect(ssl_stream.next_layer(), results.begin(), results.end());
                ssl_stream.handshake(ssl::stream_base::client);

                http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
                req.set(http::field::host, parsed_url.host);
                req.set(http::field::user_agent, "mycurl");

                http::write(ssl_stream, req);
                beast::flat_buffer buffer;
                http::response<http::dynamic_body> res;
                http::read(ssl_stream, buffer, res);

                print_response(res);
                redirect_url = handle_redirect(res, url, redirect_url, redirects, visited_urls);  // Handle potential redirects
                if (redirect_url.empty()) break;  // If no more redirects, break out of loop

                body_size = res.body().size();
                save_response(res, output_file);
            } else {
                // HTTP (non-SSL)
                asio::connect(socket, results.begin(), results.end());

                http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
                req.set(http::field::host, parsed_url.host);
                req.set(http::field::user_agent, "mycurl");

                http::write(socket, req);
                beast::flat_buffer buffer;
                http::response<http::dynamic_body> res;
                http::read(socket, buffer, res);

                print_response(res);
                redirect_url = handle_redirect(res, url, redirect_url, redirects, visited_urls);  // Handle potential redirects
                if (redirect_url.empty()) break;  // If no more redirects, break out of loop

                body_size = res.body().size();
                save_response(res, output_file);
            }

            if (!redirect_url.empty()) {
                url = redirect_url;  // Update URL with the new redirect URL
            }
        }

        auto end_time = Clock::now();
        auto duration = std::chrono::duration<double>(end_time - Clock::now()).count();
        double mbps = (body_size * 8.0) / (duration * 1e6);

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << std::put_time(std::localtime(&now), "%F %T") << " "
                  << url << " " << body_size << " [bytes] "
                  << duration << " [s] "
                  << mbps << " [Mbps]\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string url;
    std::string output_file;

    // Argument parsing using getopt
    int opt;
    while ((opt = getopt(argc, argv, "o:")) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-o output_file] URL" << std::endl;
                return 1;
        }
    }

    if (optind < argc) {
        url = argv[optind];
    } else {
        std::cerr << "URL is required!" << std::endl;
        return 1;
    }

    get_url(url, output_file);
    return 0;
}
