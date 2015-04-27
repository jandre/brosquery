#include <osquery/sdk.h>
#include "bro_table.h"

using namespace osquery;

class
BroTable: public tables::TablePlugin {
private:
    fs::path             logPath_;
    tables::TableColumns columns_;
    BroHeader            header_;

    void
    readRows(QueryData &results) {
        if (fs::exists(logPath_)) {
            std::ifstream fin(logPath_.string());

            std::string   line;
            while (std::getline(fin, line)) {
                boost::trim(line);
                if (!line.size()) {
                    continue;
                }
                if (line.at(0) != '#') {
                    header_.parse(line, results);
                }
            }
        }
    }

    void
    readColumns() {
        columns_ = header_.tableColumns();
    }

public:

    BroTable() {
        columns_ = {};
    }

    void
    setTable(BroHeader &header, fs::path &logPath) {
        header_  = header;
        logPath_ = logPath;
        readColumns();
    }

    tables::TableColumns
    columns() const {
        return columns_;
    }

    QueryData
    generate(tables::QueryContext& request) {
        QueryData results;

        readRows(results);
        return results;
    }
};

CREATE_MODULE("bro", "0.0.1", "0.0.0");

void
initModule(void) {
    fs::path logsPath = detectBroLogsPath();

    DEBUG_LOG("Loaded bro module at %s", logsPath.string().c_str());

    if (!fs::exists(logsPath) || !fs::is_directory(logsPath)) {
        /* no logs lodaed */
        return;
    }
    fs::directory_iterator end;

    for (fs::directory_iterator dir_iter(logsPath); dir_iter != end; ++dir_iter) {
        if (fs::is_regular_file(dir_iter->status()) && (dir_iter->path().extension() == ".log")) {
            auto      tableName = std::string("bro_") + dir_iter->path().stem().string();
            fs::path  tablePath = dir_iter->path();

            BroHeader header;
            if (header.read(tablePath)) {
                REGISTER_MODULE(BroTable, "table", tableName.c_str());

                /* this is a hack -- since I can't register instatiated objects, only */
                /* table types, it's hard for me to dynamically set table columns or */
                /* other structures. */
                auto table = std::dynamic_pointer_cast < BroTable > (
                    Registry::get("table", tableName.c_str()));
                table->setTable(header, tablePath);
            }
        }
    }
}

