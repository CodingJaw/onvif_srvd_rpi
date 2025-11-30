#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sstream>


#include "daemon.h"
#include "smacros.h"
#include "ServiceContext.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// ---- gsoap ----
#include "DeviceBinding.nsmap"
#include "soapDeviceBindingService.h"
#include "soapDeviceIOBindingService.h"
#include "soapMediaBindingService.h"
#include "soapPTZBindingService.h"



static bool parse_io_triplet(const char* arg, std::string& token, std::string& name, std::string& state)
{
    if(!arg)
        return false;

    std::stringstream ss(arg);

    if(!std::getline(ss, token, ':'))
        return false;

    if(!std::getline(ss, name, ':'))
        return false;

    if(!std::getline(ss, state, ':'))
        return false;

    return !(token.empty() || name.empty() || state.empty());
}


namespace
{
    constexpr int LOCAL_CONTROL_PORT = 10100;
    std::atomic<bool> local_control_running{false};
    std::thread local_control_thread;

    std::string build_http_response(int status_code, const std::string& body)
    {
        std::ostringstream os;
        os << "HTTP/1.1 " << status_code << "\r\n";
        os << "Content-Type: application/json\r\n";
        os << "Content-Length: " << body.size() << "\r\n";
        os << "Connection: close\r\n\r\n";
        os << body;
        return os.str();
    }

    bool parse_local_request(const std::string& request_line, std::string& token, bool& is_input, bool& active)
    {
        auto path_start = request_line.find(' ');
        if(path_start == std::string::npos)
            return false;

        auto path_end = request_line.find(' ', path_start + 1);
        if(path_end == std::string::npos)
            return false;

        auto path = request_line.substr(path_start + 1, path_end - path_start - 1);
        if(path.rfind("/io", 0) != 0)
            return false;

        auto qpos = path.find('?');
        if(qpos == std::string::npos)
            return false;

        auto query = path.substr(qpos + 1);
        std::istringstream ss(query);
        std::string pair;

        while(std::getline(ss, pair, '&'))
        {
            auto eq = pair.find('=');
            if(eq == std::string::npos)
                continue;

            auto key = pair.substr(0, eq);
            auto value = pair.substr(eq + 1);

            if(key == "type")
                is_input = (value != "output");
            else if(key == "token")
                token = value;
            else if(key == "state")
                active = (value == "1" || value == "true" || value == "on" || value == "active");
        }

        return !token.empty();
    }

    void local_control_loop(ServiceContext* ctx)
    {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if(server_fd < 0)
            return;

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(LOCAL_CONTROL_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if(bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0)
        {
            close(server_fd);
            return;
        }

        if(listen(server_fd, 4) < 0)
        {
            close(server_fd);
            return;
        }

        local_control_running = true;

        while(local_control_running)
        {
            int client = accept(server_fd, nullptr, nullptr);
            if(client < 0)
                continue;

            char buffer[1024];
            auto received = recv(client, buffer, sizeof(buffer) - 1, 0);

            int status = 200;
            std::string body;

            if(received > 0)
            {
                buffer[received] = '\0';
                std::string token;
                bool is_input = true;
                bool active = false;

                if(parse_local_request(buffer, token, is_input, active))
                {
                    bool ok = false;
                    ServiceContext::IOState snapshot{};

                    if(is_input)
                    {
                        ok = ctx->set_digital_input_state(token, active);
                        ctx->get_input_status(token, snapshot);
                    }
                    else
                    {
                        ok = ctx->set_relay_state(token, active ? tt__RelayLogicalState::active : tt__RelayLogicalState::inactive);
                        ctx->get_output_status(token, snapshot);
                    }

                    if(ok)
                    {
                        body = std::string("{\"token\":\"") + token + "\",\"state\":" + (snapshot.active ? "true" : "false") +
                               ",\"lastChange\":\"" + ctx->format_timestamp(snapshot.last_change) + "\"}";
                    }
                    else
                    {
                        status = 404;
                        body = "{\"error\":\"Unknown token\"}";
                    }
                }
                else
                {
                    status = 400;
                    body = "{\"error\":\"Invalid request\"}";
                }
            }
            else
            {
                status = 400;
                body = "{\"error\":\"Empty request\"}";
            }

            auto response = build_http_response(status, body);
            send(client, response.c_str(), response.size(), 0);
            close(client);
        }

        close(server_fd);
    }

    void start_local_control(ServiceContext* ctx)
    {
        if(local_control_running)
            return;

        local_control_thread = std::thread(local_control_loop, ctx);
        local_control_thread.detach();
    }
}




static const char *help_str =
        " Daemon name:  " DAEMON_NAME        "\n"
        " Daemon  ver:  " DAEMON_VERSION_STR "\n\n"
#ifdef  DEBUG
        " Build  mode:  debug\n"
#else
        " Build  mode:  release\n"
#endif
        " Build  date:  " __DATE__ "\n"
        " Build  time:  " __TIME__ "\n"
#if  COMMIT_ISDIRTY == 0
        " Build  hash:  "  COMMIT_HASH "\n\n"
#else
        " Build  hash:  *" COMMIT_HASH "\n\n"
#endif
        "Options:                      description:\n\n"
        "       --no_chdir             Don't change the directory to '/'\n"
        "       --no_fork              Don't do fork\n"
        "       --no_close             Don't close standart IO files\n"
        "       --pid_file     [value] Set pid file name\n"
        "       --log_file     [value] Set log file name\n\n"
        "       --port         [value] Set socket port for Services   (default = 1000)\n"
        "       --user         [value] Set user name for Services     (default = admin)\n"
        "       --password     [value] Set user password for Services (default = admin)\n"
        "       --rtsp_user    [value] Set RTSP authentication user   (default follows --user)\n"
        "       --rtsp_pass    [value] Set RTSP authentication pass   (default follows --password)\n"
        "       --rtsp_transport[value] Set RTSP transport (udp|tcp|rtsp|http)\n"
        "       --model        [value] Set model device for Services  (default = Model)\n"
        "       --scope        [value] Set scope for Services         (default don't set)\n"
        "       --ifs          [value] Set Net interfaces for work    (default don't set)\n"
        "       --tz_format    [value] Set Time Zone Format           (default = 0)\n"
        "       --hardware_id  [value] Set Hardware ID of device      (default = HardwareID)\n"
        "       --serial_num   [value] Set Serial number of device    (default = SerialNumber)\n"
        "       --firmware_ver [value] Set firmware version of device (default = FirmwareVersion)\n"
        "       --manufacturer [value] Set manufacturer for Services  (default = Manufacturer)\n\n"
        "       --name         [value] Set Name for Profile Media Services\n"
        "       --width        [value] Set Width for Profile Media Services\n"
        "       --height       [value] Set Height for Profile Media Services\n"
        "       --url          [value] Set URL (or template URL) for Profile Media Services\n"
        "       --snapurl      [value] Set URL (or template URL) for Snapshot\n"
        "                              in template mode %s will be changed to IP of interface (see opt ifs)\n"
        "       --type         [value] Set Type for Profile Media Services (JPEG|MPEG4|H264)\n"
        "                              It is also a sign of the end of the profile parameters\n\n"
        "       --ptz                  Enable PTZ support\n"
        "       --move_left    [value] Set process to call for PTZ pan left movement\n"
        "       --move_right   [value] Set process to call for PTZ pan right movement\n"
        "       --move_up      [value] Set process to call for PTZ tilt up movement\n"
        "       --move_down    [value] Set process to call for PTZ tilt down movement\n"
        "       --move_stop    [value] Set process to call for PTZ stop movement\n"
        "       --move_preset  [value] Set process to call for PTZ goto preset movement\n"
        "       --dio_in       [t:n:s]  Add digital input token, label and idle state (open|closed)\n"
        "       --dio_out      [t:n:s]  Add relay output token, label and state (active|inactive)\n"
        "  -v,  --version              Display daemon version\n"
        "  -h,  --help                 Display this help\n\n";




// indexes for long_opt function
namespace LongOpts
{
    enum
    {
        version = 'v',
        help    = 'h',

        //daemon options
        no_chdir = 1,
        no_fork,
        no_close,
        pid_file,
        log_file,

        //ONVIF Service options (context)
        port,
        user,
        password,
        rtsp_user,
        rtsp_pass,
        rtsp_transport,
        manufacturer,
        model,
        firmware_ver,
        serial_num,
        hardware_id,
        scope,
        ifs,
        tz_format,

        //Media Profile for ONVIF Media Service
        name,
        width,
        height,
        url,
        snapurl,
        type,

        //PTZ Profile for ONVIF PTZ Service
        ptz,
        move_left,
        move_right,
        move_up,
        move_down,
        move_stop,
        move_preset,

        dio_in,
        dio_out
    };
}



static const char *short_opts = "hv";


static const struct option long_opts[] =
{
    { "version",      no_argument,       NULL, LongOpts::version       },
    { "help",         no_argument,       NULL, LongOpts::help          },

    //daemon options
    { "no_chdir",     no_argument,       NULL, LongOpts::no_chdir      },
    { "no_fork",      no_argument,       NULL, LongOpts::no_fork       },
    { "no_close",     no_argument,       NULL, LongOpts::no_close      },
    { "pid_file",     required_argument, NULL, LongOpts::pid_file      },
    { "log_file",     required_argument, NULL, LongOpts::log_file      },

    //ONVIF Service options (context)
    { "port",         required_argument, NULL, LongOpts::port          },
    { "user",         required_argument, NULL, LongOpts::user          },
    { "password",     required_argument, NULL, LongOpts::password      },
    { "rtsp_user",    required_argument, NULL, LongOpts::rtsp_user     },
    { "rtsp_pass",    required_argument, NULL, LongOpts::rtsp_pass     },
    { "rtsp_transport",required_argument,NULL, LongOpts::rtsp_transport},
    { "manufacturer", required_argument, NULL, LongOpts::manufacturer  },
    { "model",        required_argument, NULL, LongOpts::model         },
    { "firmware_ver", required_argument, NULL, LongOpts::firmware_ver  },
    { "serial_num",   required_argument, NULL, LongOpts::serial_num    },
    { "hardware_id",  required_argument, NULL, LongOpts::hardware_id   },
    { "scope",        required_argument, NULL, LongOpts::scope         },
    { "ifs",          required_argument, NULL, LongOpts::ifs           },
    { "tz_format",    required_argument, NULL, LongOpts::tz_format     },

    //Media Profile for ONVIF Media Service
    { "name",          required_argument, NULL, LongOpts::name         },
    { "width",         required_argument, NULL, LongOpts::width        },
    { "height",        required_argument, NULL, LongOpts::height       },
    { "url",           required_argument, NULL, LongOpts::url          },
    { "snapurl",       required_argument, NULL, LongOpts::snapurl      },
    { "type",          required_argument, NULL, LongOpts::type         },

    //PTZ Profile for ONVIF PTZ Service
    { "ptz",           no_argument,       NULL, LongOpts::ptz          },
    { "move_left",     required_argument, NULL, LongOpts::move_left    },
    { "move_right",    required_argument, NULL, LongOpts::move_right   },
    { "move_up",       required_argument, NULL, LongOpts::move_up      },
    { "move_down",     required_argument, NULL, LongOpts::move_down    },
    { "move_stop",     required_argument, NULL, LongOpts::move_stop    },
    { "move_preset",   required_argument, NULL, LongOpts::move_preset  },

    //DeviceIO configuration
    { "dio_in",        required_argument, NULL, LongOpts::dio_in       },
    { "dio_out",       required_argument, NULL, LongOpts::dio_out      },

    { NULL,           no_argument,       NULL,  0                      }
};





#define FOREACH_SERVICE(APPLY, soap)            \
        APPLY(DeviceBindingService, soap)       \
        APPLY(DeviceIOBindingService, soap)     \
        APPLY(MediaBindingService, soap)        \
        APPLY(PTZBindingService, soap)          \


/*
 * If you need support for other services,
 * add the desired option to the macro FOREACH_SERVICE.
 *
 * Note: Do not forget to add the gsoap binding class for the service,
 * and the implementation methods for it, like for DeviceBindingService



        APPLY(ImagingBindingService, soap)               \
        APPLY(PTZBindingService, soap)                   \
        APPLY(RecordingBindingService, soap)             \
        APPLY(ReplayBindingService, soap)                \
        APPLY(SearchBindingService, soap)                \
        APPLY(ReceiverBindingService, soap)              \
        APPLY(DisplayBindingService, soap)               \
        APPLY(EventBindingService, soap)                 \
        APPLY(PullPointSubscriptionBindingService, soap) \
        APPLY(NotificationProducerBindingService, soap)  \
        APPLY(SubscriptionManagerBindingService, soap)   \
*/


#define DECLARE_SERVICE(service, soap) service service ## _inst(soap);

#define DISPATCH_SERVICE(service, soap)                                  \
                else if (service ## _inst.dispatch() != SOAP_NO_METHOD) {\
                    soap_send_fault(soap);                               \
                    soap_stream_fault(soap, std::cerr);                  \
                }




static struct soap *soap;

ServiceContext service_ctx;





void daemon_exit_handler(int sig)
{
    //Here we release resources

    UNUSED(sig);
    soap_destroy(soap); // delete managed C++ objects
    soap_end(soap);     // delete managed memory
    soap_free(soap);    // free the context


    unlink(daemon_info.pid_file);


    exit(EXIT_SUCCESS); // good job (we interrupted (finished) main loop)
}



void init_signals(void)
{
    set_sig_handler(SIGINT,  daemon_exit_handler); //for Ctlr-C in terminal for debug (in debug mode)
    set_sig_handler(SIGTERM, daemon_exit_handler);

    set_sig_handler(SIGCHLD, SIG_IGN); // ignore child
    set_sig_handler(SIGTSTP, SIG_IGN); // ignore tty signals
    set_sig_handler(SIGTTOU, SIG_IGN);
    set_sig_handler(SIGTTIN, SIG_IGN);
    set_sig_handler(SIGHUP,  SIG_IGN);
}



void processing_cmd(int argc, char *argv[])
{
    int opt;

    StreamProfile  profile;


    while( (opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1 )
    {
        switch( opt )
        {

            case LongOpts::help:
                        puts(help_str);
                        exit_if_not_daemonized(EXIT_SUCCESS);
                        break;

            case LongOpts::version:
                        puts(DAEMON_NAME "  version  " DAEMON_VERSION_STR "\n");
                        exit_if_not_daemonized(EXIT_SUCCESS);
                        break;


                 //daemon options
            case LongOpts::no_chdir:
                        daemon_info.no_chdir = 1;
                        break;

            case LongOpts::no_fork:
                        daemon_info.no_fork = 1;
                        break;

            case LongOpts::no_close:
                        daemon_info.no_close_stdio = 1;
                        break;

            case LongOpts::pid_file:
                        daemon_info.pid_file = optarg;
                        break;

            case LongOpts::log_file:
                        daemon_info.log_file = optarg;
                        break;


            //ONVIF Service options (context)
            case LongOpts::port:
                        service_ctx.port = atoi(optarg);
                        break;

            case LongOpts::user:
                        service_ctx.user = optarg;
                        if(service_ctx.rtsp_user.empty())
                            service_ctx.rtsp_user = service_ctx.user;
                        break;

            case LongOpts::password:
                        service_ctx.password = optarg;
                        if(service_ctx.rtsp_password.empty())
                            service_ctx.rtsp_password = service_ctx.password;
                        break;

            case LongOpts::rtsp_user:
                        service_ctx.rtsp_user = optarg;
                        break;

            case LongOpts::rtsp_pass:
                        service_ctx.rtsp_password = optarg;
                        break;

            case LongOpts::rtsp_transport:
                        if(!service_ctx.set_rtsp_transport(optarg))
                            daemon_error_exit("Can't set RTSP transport: %s\n", service_ctx.get_cstr_err());
                        break;

            case LongOpts::manufacturer:
                        service_ctx.manufacturer = optarg;
                        break;

            case LongOpts::model:
                        service_ctx.model = optarg;
                        break;

            case LongOpts::firmware_ver:
                        service_ctx.firmware_version = optarg;
                        break;

            case LongOpts::serial_num:
                        service_ctx.serial_number = optarg;
                        break;

            case LongOpts::hardware_id:
                        service_ctx.hardware_id = optarg;
                        break;

            case LongOpts::scope:
                        service_ctx.scopes.push_back(optarg);
                        break;

            case LongOpts::ifs:
                        service_ctx.eth_ifs.push_back(Eth_Dev_Param());

                        if( service_ctx.eth_ifs.back().open(optarg) != 0 )
                            daemon_error_exit("Can't open ethernet interface: %s - %m\n", optarg);

                        break;

            case LongOpts::tz_format:
                        if( !service_ctx.set_tz_format(optarg) )
                            daemon_error_exit("Can't set tz_format: %s\n", service_ctx.get_cstr_err());

                        break;


            //Media Profile for ONVIF Media Service
            case LongOpts::name:
                        if( !profile.set_name(optarg) )
                            daemon_error_exit("Can't set name for Profile: %s\n", profile.get_cstr_err());

                        break;


            case LongOpts::width:
                        if( !profile.set_width(optarg) )
                            daemon_error_exit("Can't set width for Profile: %s\n", profile.get_cstr_err());

                        break;


            case LongOpts::height:
                        if( !profile.set_height(optarg) )
                            daemon_error_exit("Can't set height for Profile: %s\n", profile.get_cstr_err());

                        break;


            case LongOpts::url:
                        if( !profile.set_url(optarg) )
                            daemon_error_exit("Can't set URL for Profile: %s\n", profile.get_cstr_err());

                        break;


            case LongOpts::snapurl:
                        if( !profile.set_snapurl(optarg) )
                            daemon_error_exit("Can't set URL for Snapshot: %s\n", profile.get_cstr_err());

                        break;


            case LongOpts::type:
                        if( !profile.set_type(optarg) )
                            daemon_error_exit("Can't set type for Profile: %s\n", profile.get_cstr_err());

                        if( !service_ctx.add_profile(profile) )
                            daemon_error_exit("Can't add Profile: %s\n", service_ctx.get_cstr_err());

                        profile.clear(); //now we can add new profile (just uses one variable)

                        break;


            //PTZ Profile for ONVIF PTZ Service
            case LongOpts::ptz:
                        service_ctx.get_ptz_node()->enable = true;
                        break;


            case LongOpts::move_left:
                        if( !service_ctx.get_ptz_node()->set_move_left(optarg) )
                            daemon_error_exit("Can't set process for pan left movement: %s\n", service_ctx.get_ptz_node()->get_cstr_err());

                        break;


            case LongOpts::move_right:
                        if( !service_ctx.get_ptz_node()->set_move_right(optarg) )
                            daemon_error_exit("Can't set process for pan right movement: %s\n", service_ctx.get_ptz_node()->get_cstr_err());

                        break;


            case LongOpts::move_up:
                        if( !service_ctx.get_ptz_node()->set_move_up(optarg) )
                            daemon_error_exit("Can't set process for tilt up movement: %s\n", service_ctx.get_ptz_node()->get_cstr_err());

                        break;


            case LongOpts::move_down:
                        if( !service_ctx.get_ptz_node()->set_move_down(optarg) )
                            daemon_error_exit("Can't set process for tilt down movement: %s\n", service_ctx.get_ptz_node()->get_cstr_err());

                        break;


            case LongOpts::move_stop:
                        if( !service_ctx.get_ptz_node()->set_move_stop(optarg) )
                            daemon_error_exit("Can't set process for stop movement: %s\n", service_ctx.get_ptz_node()->get_cstr_err());

                        break;


            case LongOpts::move_preset:
                        if( !service_ctx.get_ptz_node()->set_move_preset(optarg) )
                            daemon_error_exit("Can't set process for goto preset movement: %s\n", service_ctx.get_ptz_node()->get_cstr_err());

                        break;


            case LongOpts::dio_in:
                        {
                            std::string token;
                            std::string name;
                            std::string state;

                            if(!parse_io_triplet(optarg, token, name, state))
                                daemon_error_exit("Can't parse digital input description: %s\n", optarg);

                            if(!service_ctx.add_digital_input(token.c_str(), name.c_str(), state.c_str()))
                                daemon_error_exit("Can't add digital input: %s\n", service_ctx.get_cstr_err());
                        }

                        break;


            case LongOpts::dio_out:
                        {
                            std::string token;
                            std::string name;
                            std::string state;

                            if(!parse_io_triplet(optarg, token, name, state))
                                daemon_error_exit("Can't parse relay output description: %s\n", optarg);

                            if(!service_ctx.add_relay_output(token.c_str(), name.c_str(), state.c_str()))
                                daemon_error_exit("Can't add relay output: %s\n", service_ctx.get_cstr_err());
                        }

                        break;


            default:
                        puts("for more detail see help\n\n");
                        exit_if_not_daemonized(EXIT_FAILURE);
                        break;
        }
    }
}



void check_service_ctx(void)
{
    if(service_ctx.eth_ifs.empty())
        daemon_error_exit("Error: not set no one ehternet interface more details see opt --ifs\n");


    if(service_ctx.scopes.empty())
        daemon_error_exit("Error: not set scopes more details see opt --scope\n");


    if(service_ctx.get_profiles().empty())
        daemon_error_exit("Error: not set no one profile more details see --help\n");
}



void init_gsoap(void)
{
    soap = soap_new();

    if(!soap)
        daemon_error_exit("Can't get mem for SOAP\n");


    soap->bind_flags = SO_REUSEADDR;

    if( !soap_valid_socket(soap_bind(soap, NULL, service_ctx.port, 10)) )
    {
        soap_stream_fault(soap, std::cerr);
        exit(EXIT_FAILURE);
    }

    soap->send_timeout = 3; // timeout in sec
    soap->recv_timeout = 3; // timeout in sec


    //save pointer of service_ctx in soap
    soap->user = (void*)&service_ctx;
}



void init(void *data)
{
    UNUSED(data);
    init_signals();
    check_service_ctx();
    init_gsoap();
    start_local_control(&service_ctx);
}



int main(int argc, char *argv[])
{
    processing_cmd(argc, argv);
    daemonize2(init, nullptr);

    FOREACH_SERVICE(DECLARE_SERVICE, soap)

    while( true )
    {
        // wait new client
        if( !soap_valid_socket(soap_accept(soap)) )
        {
            soap_stream_fault(soap, std::cerr);
            return EXIT_FAILURE;
        }


        // process service
        if( soap_begin_serve(soap) )
        {
            soap_stream_fault(soap, std::cerr);
        }
        FOREACH_SERVICE(DISPATCH_SERVICE, soap)
        else
        {
            DEBUG_MSG("Unknown service\n");
        }

        soap_destroy(soap); // delete managed C++ objects
        soap_end(soap);     // delete managed memory
    }


    return EXIT_FAILURE; // Error, normal exit from the main loop only through the signal handler.
}
