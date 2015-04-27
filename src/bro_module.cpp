/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/sdk.h>
#include "bro_table.h"

using namespace osquery;

class BroTable: public tables::TablePlugin {

  private:
    fs::path logPath_;
    tables::TableColumns columns_;
    BroHeader header_;

    void readRows(QueryData &results) {
      if (fs::exists(logPath_)) {
        std::ifstream fin(logPath_.string());

        std::string line;
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

    void readColumns() {
      columns_ = header_.tableColumns();
    }

  public:

    BroTable() {
      columns_ = {};
    }

    void setTable(BroHeader &header, fs::path &logPath) {
      header_ = header;
      logPath_ = logPath;
      readColumns();
    }

    tables::TableColumns columns() const {
      return columns_;
    }

    QueryData generate(tables::QueryContext& request) {
      QueryData results;
      readRows(results);
      return results;
    }
};

CREATE_MODULE("bro", "0.0.1", "0.0.0");

void initModule(void) {

  fs::path logsPath = detectBroLogsPath();

  if (fs::exists(logsPath) && fs::is_directory(logsPath)) {

    fs::directory_iterator end;
    for(fs::directory_iterator dir_iter(logsPath); dir_iter != end; ++dir_iter)
    {
      if (fs::is_regular_file(dir_iter->status()) &&
          (dir_iter->path().extension() == ".log")) {

        auto tableName = std::string("bro_") + dir_iter->path().stem().string();
        fs::path tablePath = dir_iter->path();

        BroHeader header;
        if (header.read(tablePath)) {
          REGISTER_MODULE(BroTable, "table", tableName.c_str());
          auto table = std::dynamic_pointer_cast<BroTable>(
              Registry::get("table", tableName.c_str()));
          table->setTable(header, tablePath);
          // fprintf(stderr, "XXX: bro module loaded %s\n", tableName.c_str());
        }
      }
    }
  }
}
