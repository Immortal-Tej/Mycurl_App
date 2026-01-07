#include <getopt.h>
#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <iomanip>
#include <regex>
#include <set>
#include <ctime>
#include <sstream>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

struct Url {
    std::string scheme, host, port, path;
};

Url parse_url(const std::string& url) {
    std::regex url_regex("(https?)://([^/]+)(/.*)?");
    std::smatch match;
    if (!std::regex_match(url, match, url_regex)) {
        throw std::invalid_argument("error");
    }

    Url parsed_url;
    parsed_url.scheme = match[1].str();
    parsed_url.host = match[2].str();
    parsed_url.path = match[3].matched ? match[3].str() : "/";
    parsed_url.port = (parsed_url.scheme == "https") ? "443" : "80";

    return parsed_url;
}

void print_response(const http::response<http::dynamic_body>& res, bool silent) {
    if (!silent) {
        for (const auto& header : res.base()) {
            std::cout << header.name_string() << ": " << header.value() << "\n";
        }
    }
}

void save_response(const http::response<http::dynamic_body>& res, const std::string& outfile) {
    if (!outfile.empty()) {
        std::ofstream ofs(outfile, std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("error");
        }
        ofs << boost::beast::buffers_to_string(res.body().data());
        ofs.close();
    }
}

std::string handle_redirect(http::response<http::dynamic_body>& res, const std::string& url, std::string& redirect_url, size_t& redirects, std::set<std::string>& visited_urls) {
    if (res.result_int() >= 300 && res.result_int() < 400 && res.base().count(http::field::location)) {
        redirect_url = res.base()[http::field::location].to_string();
        if (visited_urls.find(redirect_url) != visited_urls.end() || redirect_url == url) {
            std::cout << "error" << std::endl;
            return "";
        }
        visited_urls.insert(redirect_url);
        ++redirects;
        if (redirects > 10) {
            std::cout << "error" << std::endl;
            return "";
        }
        return redirect_url;
    }
    return "";
}

void get_url(std::string& url, const std::string& output_file, bool silent) {
    try {
        Url parsed_url = parse_url(url);

        asio::io_context io_context;
        tcp::resolver resolver(io_context);

        auto results = resolver.resolve(parsed_url.host, parsed_url.port);

        std::string redirect_url;
        size_t redirects = 0;
        size_t body_size = 0;

        std::set<std::string> visited_urls;
        visited_urls.insert(url);

        auto start_time = Clock::now();

        while (true) {
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

                print_response(res, silent);
                body_size = res.body().size();
                save_response(res, output_file);

                redirect_url = handle_redirect(res, url, redirect_url, redirects, visited_urls);
                if (redirect_url.empty()) {
                    break;
                }

                url = redirect_url;
                parsed_url = parse_url(url);
                results = resolver.resolve(parsed_url.host, parsed_url.port);
            } else {
                tcp::socket socket(io_context);
                asio::connect(socket, results.begin(), results.end());

                http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
                req.set(http::field::host, parsed_url.host);
                req.set(http::field::user_agent, "mycurl");

                http::write(socket, req);
                beast::flat_buffer buffer;
                http::response<http::dynamic_body> res;
                http::read(socket, buffer, res);

                print_response(res, silent);
                body_size = res.body().size();
                save_response(res, output_file);

                redirect_url = handle_redirect(res, url, redirect_url, redirects, visited_urls);
                if (redirect_url.empty()) {
                    break;
                }

                url = redirect_url;
                parsed_url = parse_url(url);
                results = resolver.resolve(parsed_url.host, parsed_url.port);
            }
        }

        auto end_time = Clock::now();
        auto duration = std::chrono::duration<double>(end_time - start_time).count();
        if (duration <= 0) {
            duration = 1e-9;
        }
        double mbps = (body_size * 8.0) / (duration * 1e6);

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << std::put_time(std::localtime(&now), "%F %T") << " "
                  << url << " " << body_size << " [bytes] "
                  << duration << " [s] "
                  << mbps << " [Mbps]\n";

    } catch (const std::exception&) {
        std::cout << "error" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::string url;
    std::string output_file;
    bool silent = false;

    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"silent", no_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "o:s", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'o':
                output_file = optarg;
                break;
            case 's':
                silent = true;
                break;
            default:
                break;
        }
    }

    if (optind < argc) {
        url = argv[optind];
    } else {
        std::cout << "error" << std::endl;
        return 1;
    }

    if (silent && output_file.empty()) {
        std::cout << "error" << std::endl;
        return 1;
    }

    get_url(url, output_file, silent);
    return 0;
}
