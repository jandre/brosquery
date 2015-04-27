#include <osquery/sdk.h>
#include <boost/filesystem/operations.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

using namespace osquery;

// The path to the default bro logs folder.
// You can re-set this using -DBRO_LOGS_FOLDER=... in cmake
#ifndef DEFAULT_BRO_LOGS_FOLDER
#define DEFAULT_BRO_LOGS_FOLDER "/opt/bro/logs"
#endif

fs::path detectBroLogsPath();

class BroField {
  public:
    std::string name_;
    int position_;
    std::string type_;
    std::string tableType_;

    BroField(std::string &name, int pos, std::string &type) {
      name_ = name;
      boost::replace_all(name_, ".", "_");
      position_ = pos;
      type_ = type;
    }
    
    void setType(std::string);
    std::string tableType() const;
    std::string name() const;

};

class BroHeader {

  private:
    bool ready_ = false;
    std::string unset_field_;
    std::string empty_field_;

    void readFields(std::string &input);
    void readTypes(std::string &input);

  public:
    std::vector<BroField> fields;
    std::string separator;

    BroHeader() : ready_(false) {}

    bool read(fs::path&);
    void readHeader(std::string &);
    void parse(std::string &, QueryData &);
    tables::TableColumns tableColumns() const;
};

