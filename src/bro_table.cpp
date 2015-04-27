/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "bro_table.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
using namespace osquery;

fs::path detectBroLogsPath() {
  fs::path logsPath;

  // use environment variable BRO_LOGS if it exists.
  if ((getenv("BROPATH")) != NULL) {
    logsPath = fs::path(getenv("BROPATH")) / fs::path("logs");
  } else {
    logsPath = DEFAULT_BRO_LOGS_FOLDER;
  }

  return logsPath;
}

std::string BroField::name() const {
  return name_;
}

std::string BroField::tableType() const {
  return tableType_;
}

void BroField::setType(std::string type) {
  type_ = type;
  tableType_ = "TEXT";
  if (type_ == "count" || type_ == "port" || type_ == "int") {
    tableType_ = "INTEGER";
  }
}

void BroHeader::readFields(std::string &input) {
  int pos = 0;
  auto empty = std::string("");
  auto fields = split(input, this->separator);
  for (auto &name:fields) {
    // fprintf(stderr, "XXX: read field: %s\n", name.c_str());
    this->fields.push_back(BroField(name, pos++, empty));
  }
}

void BroHeader::readTypes(std::string &input) {
  auto types = split(input, this->separator);
  int pos = 0;
  for (auto &type:types) {
    this->fields[pos++].setType(type);
  }
}

bool BroHeader::read(fs::path &logPath) {

  if (fs::exists(logPath)) {
    std::ifstream fin(logPath.string());
    std::string line;

    while (std::getline(fin, line)) {
      boost::trim(line);

      if (!line.size()) {
        continue;
      }
      if (line.at(0) == '#') {
        readHeader(line);
      } else {
        break;
      }
    }
  }
  return ready_;
}

void BroHeader::readHeader(std::string &line) {
  if (boost::starts_with(line, "#separator")) {
    auto sep = line.substr(strlen("#separator") + 1);
    if (boost::starts_with(sep, "\\x")) {
      sep = sep.substr(2);
      unsigned int x;
      std::stringstream ss(sep);
      ss >> std::hex >> x;
      this->separator = std::string(" ");
      this->separator[0] = (char)x;
    } else {
      this->separator = sep;
    }
  }
  else if (boost::starts_with(line, "#empty_field")) {
    auto empty_field = line.substr(strlen("#empty_field") + this->separator.size());
    empty_field_ = empty_field;
  }
  else if (boost::starts_with(line, "#unset_field")) {
    auto unset_field = line.substr(strlen("#unset_field") + this->separator.size());
    unset_field_ = unset_field;
  }
  else if (boost::starts_with(line, "#fields")) {
    auto fields = line.substr(strlen("#fields") + 1);
    this->readFields(fields);
  } else if (boost::starts_with(line, "#types")) {
    auto types = line.substr(strlen("#types"));
    this->readTypes(types);
  ready_ = true;
  }
}

void BroHeader::parse(std::string &line, QueryData &results) {
  auto vals = split(line, this->separator);
  int pos = 0;
  Row row;

  if (vals.size() != this->fields.size()) {
    return;
  }
  for (auto &val : vals) {
    auto &field = this->fields[pos++];
    if (val == unset_field_ || val == empty_field_) {
      if (field.tableType_ == "INTEGER") {
        row[field.name()] = "-1" ;
      } else {
        row[field.name()] = "";
      }
    } else {
      row[field.name()] = val;
    }
  }
  results.push_back(row);
}

tables::TableColumns BroHeader::tableColumns() const {
  tables::TableColumns result;
  for (auto &field: this->fields) {
    result.push_back(std::pair<std::string,std::string>(
         field.name(),
         field.tableType()));
  }
  return result;
}

