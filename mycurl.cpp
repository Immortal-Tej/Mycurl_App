#include <iostream>
#include <string>
#include <stdexcept>
#include <regex>
#include <chrono>
#include <iomanip>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <filesystem>
#include <getopt.h>

namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;

struct Url {
    std::string scheme;
    std::string host;
    std::string port;
    std::string target;
};

std::optional<Url> parse_url(const std::string& url) {
    std::regex url_regex(R"((https?)://([^:/]+)(?::(\d+))?(/.*)?)");
    std::smatch match;

    if (std::regex_match(url, match, url_regex)) {
        Url result;
        result.scheme = match[1].str();
        result.host = match[2].str();
        result.port = match[3].matched ? match[3].str() : (result.scheme == "https" ? "443" : "80");
        result.target = match[4].matched ? match[4].str() : "/";
        return result;
    }
    return std::nullopt;
}

void display_certificate_info(ssl::stream<tcp::socket>& stream) {
    X509* cert = SSL_get_peer_certificate(stream.native_handle());
    if (!cert) {
        std::cerr << "Error: No certificate found.\n";
        return;
    }

    std::string subj(512, '\0');
    std::string iss(512, '\0');

    if (X509_NAME_oneline(X509_get_subject_name(cert), &subj[0], subj.size()) == nullptr ||
        X509_NAME_oneline(X509_get_issuer_name(cert), &iss[0], iss.size()) == nullptr) {
        std::cerr << "Error: Failed to get certificate details.\n";
        X509_free(cert);
        return;
    }

    std::cout << "Server certificate:\n"
              << "  Subject: " << subj << "\n"
              << "  Issuer:  " << iss << "\n";
    X509_free(cert);
}

bool perform_request(const std::string& url, const std::string& outfile, std::string& redirect, std::size_t& body_size) {
    auto u = parse_url(url);
    if (!u) {
        std::cerr << "Invalid URL format.\n";
        return false;
    }

    net::io_context ioc;
    tcp::resolver resolver(ioc);
    redirect.clear();
    body_size = 0;

    auto results = resolver.resolve(u->host, u->port);
    auto handle_response = [&](auto& stream) -> bool {
        http::request<http::empty_body> req{http::verb::get, u->target, 11};
        req.set(http::field::host, u->host);
        req.set(http::field::user_agent, "mycurl");

        http::write(stream, req);
        beast::flat_buffer buffer;

        if (outfile.empty()) {
            http::response<http::dynamic_body> res;
            http::read(stream, buffer, res);

            for (auto const& h : res.base()) std::cout << h.name_string() << ": " << h.value() << "\n";

            if (res.result_int() >= 300 && res.result_int() < 400 && res.base().count(http::field::location)) {
                redirect = res.base()[http::field::location].to_string();
                return true;
            }

            body_size = res.body().size();
            return false;
        }

        http::response<http::file_body> res;
        beast::error_code ec;
        res.body().open(outfile.c_str(), beast::file_mode::write, ec);
        if (ec) throw beast::system_error(ec);

        http::read(stream, buffer, res);

        for (auto const& h : res.base()) std::cout << h.name_string() << ": " << h.value() << "\n";

        res.body().close();
        body_size = std::filesystem::file_size(outfile);
        return false;
    };

    try {
        if (u->scheme == "https") {
            ssl::context ctx(ssl::context::tls_client);
            ctx.set_default_verify_paths();

            ssl::stream<tcp::socket> stream(ioc, ctx);
            SSL_set_tlsext_host_name(stream.native_handle(), u->host.c_str());
            net::connect(stream.next_layer(), results);
            stream.handshake(ssl::stream_base::client);

            display_certificate_info(stream);
            return handle_response(stream);
        } else {
            tcp::socket socket(ioc);
            net::connect(socket, results);
            return handle_response(socket);
        }
    } catch (const beast::system_error& se) {
        std::cerr << "Error: " << se.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    try {
        std::string outfile;
        std::string redirect;
        std::size_t body_size = 0;
        int redirects = 0;

        static option opts[] = {
            {"output", required_argument, nullptr, 'o'},
            {0, 0, 0, 0}
        };

        int c;
        while ((c = getopt_long(argc, argv, "o:", opts, nullptr)) != -1) {
            if (c == 'o') {
                outfile = optarg;
            } else {
                std::cout << "Error: unsupported option\n";
                return 1;
            }
        }

        if (optind >= argc) {
            std::cout << "Error: missing URL\n";
            return 1;
        }

        std::string url = argv[optind];
        auto t0 = std::chrono::steady_clock::now();

        while (true) {
            bool is_redirect = perform_request(url, "", redirect, body_size);
            if (!is_redirect) break;

            std::cout << "Redirecting to: " << redirect << "\n";
            url = redirect;

            if (++redirects > 10) {
                std::cout << "Error: too many redirects\n";
                return 1;
            }
        }

        perform_request(url, outfile, redirect, body_size);

        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();
        double mbps = (body_size * 8.0) / (secs * 1e6);

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << std::put_time(std::localtime(&now), "%F %T") << " "
                  << url << " "
                  << body_size << " [bytes] "
                  << std::fixed << std::setprecision(6)
                  << secs << " [s] "
                  << mbps << " [Mbps]\n";

        return 0;
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
        return 1;
    }
}
