#pragma once

#include <chrono>
#include <cstdarg>
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#define LogEventGen(level, timestamp) \
  std::make_shared<LogEvent>(level, __FILE__, __LINE__, __FUNCTION__, timestamp)

#define LogEventGen2(level) \
  std::make_shared<LogEvent>(level, __FILE__, __LINE__, __FUNCTION__, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count())

#define LogEventWrapperGen(pLogger, level, timestamp) \
  std::make_shared<LogEventWrapper>(LogEventGen(level, timestamp), pLogger)

#define LogEventWrapperGen2(pLogger, level) \
  std::make_shared<LogEventWrapper>(LogEventGen2(level), pLogger)

#define LOG_STREAM(pLogger, level) \
  LogEventWrapperGen2(pLogger, level)->getSS()

#define LOG_ROOT()       LogManager::instance()->getRoot()
#define GET_LOGGER(name) LogManager::instance()->getLogger(name)

#define ILOG_DEBUG_FMT(pLogger, fmt, ...) \
  LogEventWrapperGen2(pLogger, LogLevel::LDEBUG)->getEvent()->format(fmt, ##__VA_ARGS__)
#define ILOG_INFO_FMT(pLogger, fmt, ...) \
  LogEventWrapperGen2(pLogger, LogLevel::LINFO)->getEvent()->format(fmt, ##__VA_ARGS__)
#define ILOG_WARN_FMT(pLogger, fmt, ...) \
  LogEventWrapperGen2(pLogger, LogLevel::LWARN)->getEvent()->format(fmt, ##__VA_ARGS__)
#define ILOG_ERROR_FMT(pLogger, fmt, ...) \
  LogEventWrapperGen2(pLogger, LogLevel::LERROR)->getEvent()->format(fmt, ##__VA_ARGS__)
#define ILOG_FATAL_FMT(pLogger, fmt, ...) \
  LogEventWrapperGen2(pLogger, LogLevel::LFATAL)->getEvent()->format(fmt, ##__VA_ARGS__)

#define ILOG_DEBUG(pLogger) \
  LOG_STREAM(pLogger, LogLevel::LDEBUG)
#define ILOG_INFO(pLogger) \
  LOG_STREAM(pLogger, LogLevel::LINFO)
#define ILOG_WARN(pLogger) \
  LOG_STREAM(pLogger, LogLevel::LWARN)
#define ILOG_ERROR(pLogger) \
  LOG_STREAM(pLogger, LogLevel::LERROR)
#define ILOG_FATAL(pLogger) \
  LOG_STREAM(pLogger, LogLevel::LFATAL)

#define LOG_DEBUG_FMT(fmt, ...) \
  LogEventWrapperGen2(LOG_ROOT(), LogLevel::LDEBUG)->getEvent()->format(fmt, ##__VA_ARGS__)
#define LOG_INFO_FMT(fmt, ...) \
  LogEventWrapperGen2(LOG_ROOT(), LogLevel::LINFO)->getEvent()->format(fmt, ##__VA_ARGS__)
#define LOG_WARN_FMT(fmt, ...) \
  LogEventWrapperGen2(LOG_ROOT(), LogLevel::LWARN)->getEvent()->format(fmt, ##__VA_ARGS__)
#define LOG_ERROR_FMT(fmt, ...) \
  LogEventWrapperGen2(LOG_ROOT(), LogLevel::LERROR)->getEvent()->format(fmt, ##__VA_ARGS__)
#define LOG_FATAL_FMT(fmt, ...) \
  LogEventWrapperGen2(LOG_ROOT(), LogLevel::LFATAL)->getEvent()->format(fmt, ##__VA_ARGS__)


#define LOG_DEBUG() \
  LOG_STREAM(LOG_ROOT(), LogLevel::LDEBUG)
#define LOG_INFO() \
  LOG_STREAM(LOG_ROOT(), LogLevel::LINFO)
#define LOG_WARN() \
  LOG_STREAM(LOG_ROOT(), LogLevel::LWARN)
#define LOG_ERROR() \
  LOG_STREAM(LOG_ROOT(), LogLevel::LERROR)
#define LOG_FATAL() \
  LOG_STREAM(LOG_ROOT(), LogLevel::LFATAL)


constexpr const char *kDefaultFormatPattern = 
  "$DATETIME{%Y-%m-%d %H:%M:%S}"
  "$CHAR:\t$LOG_NAME$CHAR:[$LOG_LEVEL$CHAR:]"
  "$CHAR:\t$FILENAME$CHAR::$LINE"
  "$CHAR:\t$FUNCTION_NAME"
  "$CHAR:\n$MESSAGE$CHAR:\n";

/**
 $MESSAGE      消息
 $LOG_LEVEL    日志级别
 $LOG_NAME     日志名称
 $CHAR:\n      换行符 \n
 $CHAR:\t      制表符 \t
 $CHAR:[       括号[
 $CHAR:]       括号]
 $DATETIME     时间
 $LINE         行号
 $FILENAME     文件名

 默认格式：
  "$DATETIME{%Y-%m-%d %H:%M:%S}"
  "$CHAR:\t$THREAD_NAME$CHAR:[$THREAD_ID:%FIBER_ID$CHAR:]"
  "$CHAR:\t$LOG_NAME$CHAR:[$LOG_LEVEL$CHAR:]"
  "$CHAR:\t$FILENAME$CHAR::$LINE"
  "$CHAR:\t$FUNCTION_NAME"
  "$CHAR:\n$MESSAGE$CHAR:\n"
*/
// 日志级别
struct LogLevel
{
	enum Level : int
  {
		LUNKNOWN = 0,
		LDEBUG   = 1,
		LINFO    = 2,
		LWARN    = 3,
		LERROR   = 4,
		LFATAL   = 5
		/* CUSTOM */
	};

	/**
	 * @brief 将日志级别转成文本输出
	 * @param[in] level 日志级别
	 */
	static std::string toString(LogLevel::Level level)
	{
    switch (level)
    {
    case LogLevel::Level::LDEBUG:
      return "DEBUG";
    case LogLevel::Level::LINFO:
      return "INFO";
    case LogLevel::Level::LWARN:
      return "WARN";
    case LogLevel::Level::LERROR:
      return "ERROR";
    case LogLevel::Level::LFATAL:
      return "FATAL";
    default:
      return "NONE";
    }

    return {};
	}

	/**
	 * @brief 将文本转换成日志级别
	 * @param[in] str 日志级别文本
	 */
	static LogLevel::Level fromString(const std::string &str)
	{
    if (str == "DEBUG") { return LogLevel::Level::LDEBUG; }
    if (str == "INFO") { return LogLevel::Level::LINFO; }
    if (str == "WARN") { return LogLevel::Level::LWARN; }
    if (str == "ERROR") { return LogLevel::Level::LERROR; }
    if (str == "FATAL") { return LogLevel::Level::LFATAL; }

    return LogLevel::LUNKNOWN;
	}
};

class Logger;

struct LogColorConfig
{
  enum ColorType : int
  {
    END = 0,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    DEEP_RED,
  };

  const char *colors[6] = {
    "\033[0m",
    "\033[31m",
    "\033[32m",
    "\033[33m",
    "\033[34m",
    "\033[35m",
  };

  int LOG_END = END;
  int LOG_LEVEL_DEBUG = BLUE;
  int LOG_LEVEL_INFO = GREEN;
  int LOG_LEVEL_WARN = YELLOW;
  int LOG_LEVEL_ERROR = RED;
  int LOG_LEVEL_FATAL = DEEP_RED;

  const char *getColor(int type) const
  {
    return colors[type];
  }
};

// 日志事件
class LogEvent
{
public:
  using ptr = std::shared_ptr<LogEvent>;

  /**
   * @brief 构造函数
   * @param[in] pLogger     日志器
   * @param[in] level       日志级别
   * @param[in] filename    文件名
   * @param[in] line        文件行号
   * @param[in] timestamp   日志事件发生的时间
   * @param[in] config      日志颜色显示配置
   */
  LogEvent(LogLevel::Level level, 
           std::string filename, int32_t line, std::string function_name, 
           int64_t timestamp, 
           LogColorConfig config = LogColorConfig()) :
    level_(level),
    filename_(filename), line_(line), function_name_(function_name),
    timestamp_(timestamp)
  {}

  std::string getFilename() const { return filename_; }
  std::string getFunctionName() const { return function_name_; }
  int32_t getLine() const { return line_; }
  int64_t getTimestamp() const { return timestamp_; }
  std::string getContent() const { return ss_.str(); }
  LogLevel::Level getLevel() const { return level_; }
  void setLogColorOn(bool on) { color_on_ = on; }
  bool isLogColorOn() const { return color_on_; }
  LogColorConfig getColorConfig() const { return color_config_; }
  std::stringstream &getSS() { return ss_; }

  void format(const char *fmt, ...)
  {
    va_list args;
    char buf[256]{ 0 };

    va_start(args, fmt);
    int len = vsnprintf(&buf[0], sizeof(buf), fmt, args);
    if (len < 0) {
      va_end(args);
      return;
    }

    ss_ << std::string(buf, len);
    va_end(args);
  }

private:
  /// 文件名
  std::string filename_;
  /// 函数名
  std::string function_name_;
  /// 行号
  int32_t line_ = 0;
  /// 时间戳
  int64_t timestamp_ = 0;
  /// 日志内容流
  std::stringstream ss_;
  /// 日志等级
  LogLevel::Level level_;
  /// 颜色配置
  LogColorConfig color_config_;
  bool color_on_{false};
};

class LogEventWrapper;

// 日志格式器
class LogFormatter
{
protected:
  static constexpr char ID_TOKEN = '$';
  static constexpr int FORMAT_ID_LOC = 0;
  static constexpr int FORMAT_FN_ARG_LOC = 1;
  static constexpr int STATUS_CODE_LOC = 2;

  enum {
    PARSE_OK = 0,
    PARSE_ERROR = 1,
  };

  using PatArgsWrapper = std::tuple<std::string, std::string, int>;
public:
  using ptr = std::shared_ptr<LogFormatter>;

  LogFormatter(std::string pattern = kDefaultFormatPattern) :
    pattern_(pattern)
  {
    init();
  }

  /**
   * @brief 返回格式化日志文本
   * @param[in] pLogEvent
   * @param[in] pLogger
   */
  std::string format(LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger)
  {
    std::stringstream ss;
    for (auto &item : items_) {
      item->format(ss, pLogEvent, pLogger);
    }
    return ss.str();
  }
  std::ostream &format(std::ostream &ofs, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger)
  {
    std::stringstream ss;
    for (auto &item : items_) {
      item->format(ss, pLogEvent, pLogger);
    }
    ofs << ss.str();
    ofs.flush();
    return ofs;
  }

  bool hasError() const { return hasError_; }
  const std::string lastError() const { return error_; }
  const std::string getPattern() const { return pattern_; }
private:
  PatArgsWrapper parsePatToken(const std::string& patToken)
  {
    if (patToken.find("CHAR:") == 0) {
      if (patToken.length() <= 5) return std::make_tuple("CHAR", "", PARSE_ERROR);
      auto ch = patToken.substr(5);
      return std::make_tuple("CHAR", ch, PARSE_OK);
    }
    if (patToken.find("DATETIME") == 0) {
      if (patToken.length() > 8 && patToken[8] == '{') {
        size_t timefmt_len = patToken.rfind('}');
        if (timefmt_len >= 9) {
          timefmt_len -= 9;
          auto timefmt = patToken.substr(9, timefmt_len);
          return std::make_tuple("DATETIME", timefmt, PARSE_OK);
        }
        else {
          // error timefmt
          return std::make_tuple(patToken, "", PARSE_ERROR);
        }
      }
      else {
        // Default DATETIME format
        return std::make_tuple("DATETIME", "%Y-%m-%d %H:%M:%S", PARSE_OK);
      }
    }
    // NO PARAM ARG
    return { patToken, "", PARSE_OK };
  }
  void init()
  {
    std::vector<PatArgsWrapper> vec;
    std::string nstr;
    size_t start_pos = 0, len = 0;
    for (size_t i = 0; i < pattern_.size(); ++i) {
      if (pattern_[i] == ID_TOKEN) {
        if (len != 0) {
          nstr = pattern_.substr(start_pos, len);
          vec.push_back(parsePatToken(nstr));
        }

        start_pos = i + 1;
        len = 0;
        continue;
      }

      ++len;
    }

    if (len != 0) {
      nstr = pattern_.substr(start_pos, len);
      vec.push_back(parsePatToken(nstr));
    }
    else {
      // $
      vec.push_back(std::make_tuple("", "", PARSE_ERROR));
    }

    static std::unordered_map<std::string, std::function<LogFormatterItem::ptr(const std::string &str)> >
      s_format_items = {
  #define XX(STR, ID) \
      { STR, [](const std::string& str) -> LogFormatterItem::ptr { return std::make_shared<ID>(str);} }
        XX("LOG_LEVEL"    , LogLevelFormatterItem),
        XX("MESSAGE"      , MessageFormatterItem),
        XX("LOG_NAME"     , LogNameFormatterItem),
        XX("DATETIME"     , DateTimeFormatterItem),
        XX("FILENAME"     , FilenameFormatterItem),
        XX("LINE"         , LineFormatterItem),
        XX("CHAR"         , CharFormatterItem),
        XX("FUNCTION_NAME", FunctionNameFormatterItem),
  #undef XX
    };

    hasError_ = false;
    for (const auto &wrapper : vec) {
      const auto &[id, arg, status] = wrapper;
      if (status != PARSE_OK) {
        items_.push_back(std::make_shared<StringFormatterItem>(id));
        continue;
      }

      auto it = s_format_items.find(id);
      if (it == s_format_items.end()) {
        hasError_ = true;
        error_.clear();
        error_.append("<<PATTERN ERROR: UNSUPPORTED FORMAT $");
        error_.append(id);
        error_.append(">>");
        items_.push_back(std::make_shared<StringFormatterItem>(error_));
      }
      else {
        items_.push_back(it->second(arg));
      }
    }
  }

private:
	struct LogFormatterItem
	{
    using ptr = std::shared_ptr<LogFormatterItem>;
    /**
     * @brief 析构函数
     */
    virtual ~LogFormatterItem() = default;
    /**
     * @brief 格式化日志到流
     * @param[in, out] os 日志输出流
     * @param[in] pLogEvent 日志事件包装器
     * @param[in] pLogger 日志器
     */
    virtual void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) = 0;
	};

  /// LogFormatterItem
  class MessageFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    MessageFormatterItem(const std::string &str = "") {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;
  };
  class LogLevelFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    LogLevelFormatterItem(const std::string &str = "") {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;
  };
  class LogNameFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    LogNameFormatterItem(const std::string &str = "") {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;
  };
  class DateTimeFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    DateTimeFormatterItem(const std::string &format = "%Y-%m-%d %H:%M:%S")
      :timefmt_(format) {
      if (timefmt_.empty()) {
        timefmt_ = "%Y-%m-%d %H:%M:%S";
      }
    }
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;

  private:
    std::string timefmt_;
  };
  class FilenameFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    FilenameFormatterItem(const std::string &str = "") {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;
  };
  class LineFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    LineFormatterItem(const std::string &str = "") {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;
  };
  class StringFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    StringFormatterItem(const std::string &str)
      :str_(str) {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;

  private:
    std::string str_;
  };
  class CharFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    CharFormatterItem(const std::string &str = "") :
      str_(str)
    {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;

  private:
    std::string str_;
  };
  class FunctionNameFormatterItem final : public LogFormatter::LogFormatterItem {
  public:
    FunctionNameFormatterItem(const std::string &str)
      :str_(str) {}
    void format(std::ostream &os, LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override;

  private:
    std::string str_;
  };

private:
  /// 日志格式模板
  std::string pattern_;
  /// 日志格式解析后格式
  std::vector<LogFormatterItem::ptr> items_;
  /// 错误信息
  std::string error_;
  bool hasError_{false};
};

// 日志添加器
class LogAppender
{
public:
  using ptr = std::shared_ptr<LogAppender>;

  LogAppender() = default;
  virtual ~LogAppender() = default;

  virtual void log(LogEvent::ptr pEvent, std::shared_ptr<Logger> pLogger) = 0;

  void setFormatter(LogFormatter::ptr pFormatter)
  {
    std::lock_guard<std::mutex> locker(mutex_);
    pFormatter_ = pFormatter;
    if (pFormatter_) {
      hasFormatter_ = true;
    }
    else {
      hasFormatter_ = false;
    }
  }
  LogFormatter::ptr getFormatter()
  {
    std::lock_guard<std::mutex> locker(mutex_);
    return pFormatter_;
  }
  
  LogLevel::Level getLevel() const { return level_; }
  void setLevel(LogLevel::Level level) { level_ = level; }
protected:
  /// 日志级别
  LogLevel::Level level_{LogLevel::LDEBUG};
  /// 是否有自己的日志格式器
  bool hasFormatter_{false};
  /// Mutex
  std::mutex mutex_;
  /// 日志格式器
  LogFormatter::ptr pFormatter_;
};
class FileLogAppender : public LogAppender
{
public:
  using ptr = std::shared_ptr<FileLogAppender>;

	FileLogAppender(std::string filename) :
    filename_(filename)
  {
    reopen();
  }
	virtual ~FileLogAppender() = default;

  virtual void log(LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override
  {
    if (pLogEvent->getLevel() >= level_) {
      uint64_t now = pLogEvent->getTimestamp();
      if (now >= (lastAccessTime_ + 3)) {
        reopen();
        lastAccessTime_ = now;
      }

      std::lock_guard<std::mutex> locker(mutex_);
      if (!pFormatter_->format(filestream_, pLogEvent, pLogger)) {
        std::cerr << "error in " << "FileLogAppender::log" << " with Formatter format" << std::endl;
        std::cerr << "log file cannot be created" << std::endl;
      }
      else {
        lines_++;
        if (lines_ >= kMaxLines) {
          cnt_++;
          lines_ = 0;
        }
      }
    }
  }

  /**
   * @brief 重新打开日志文件
   * @return 成功返回true
   */
  bool reopen()
  {
    std::lock_guard<std::mutex> locker(mutex_);
    if (filestream_) {
      filestream_.close();
    }

    // filestream_.open(filename_, std::ios::app);
    filestream_.open(getWholeFilename(), std::ios::app);
    return filestream_.is_open();
  }
private:
  std::string getWholeFilename()
  {
    std::string wholeFilename;
    time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm tm = *localtime(&t);

    char todayStr[30];
    std::strftime(todayStr, 20, "%Y-%m-%d", &tm);
    int today = tm.tm_yday;
    if (today != today_) {
      today_ = today;
      cnt_ = 0;
    }
    wholeFilename.append(filename_);
    wholeFilename.append("_");
    wholeFilename.append(todayStr);
    wholeFilename.append("_");
    if (cnt_ < 10)
      wholeFilename.append("0");
    wholeFilename.append(std::to_string(cnt_));
    wholeFilename.append(".log");

    return wholeFilename;
  }

protected:
  // TODO:
  // can be defined in 'LogEnv' by ini or other config file
  static constexpr uint64_t kMaxLines = 100000;
private:
  /* real filename: filename_ + "_" + current_day + "_" + cnt{02d} + ".log" */
  std::string filename_;
  std::ofstream filestream_;
  uint64_t lastAccessTime_{0};
  uint64_t lines_{0}; 
  uint8_t cnt_{0};  // cnt_ incr when lines_ encounters kMaxLines
  int today_;
};
class StdoutLogAppender : public LogAppender
{
public:
  using ptr = std::shared_ptr<StdoutLogAppender>;

	StdoutLogAppender() = default;
  virtual ~StdoutLogAppender() = default;

  virtual void log(LogEvent::ptr pLogEvent, std::shared_ptr<Logger> pLogger) override
  {
    if (pLogEvent->getLevel() >= level_) {
      std::lock_guard<std::mutex> locker(mutex_);
      pLogEvent->setLogColorOn(true);
      pFormatter_->format(std::cout, pLogEvent, pLogger);
      pLogEvent->setLogColorOn(false);
    }
  }
private:

};

class Logger : public std::enable_shared_from_this<Logger>
{
public:
	using ptr = std::shared_ptr<Logger>;

  Logger(std::string name = "root") :
    name_(name), level_(LogLevel::Level::LDEBUG ),
    pFormatter_(new LogFormatter())
  {}
  Logger(std::string name, LogLevel::Level level, std::string pattern) :
    name_(name), level_(level),
    pFormatter_(new LogFormatter(pattern))
  {}
  ~Logger() = default;

  void log(LogEvent::ptr pLogEvent)
  {
    if (level_ <= pLogEvent->getLevel()) {
      auto self = shared_from_this();
      std::lock_guard<std::mutex> locker(mutex_);
      if (!appenders_.empty()) {
        for (auto &pAppender : appenders_) {
          pAppender->log(pLogEvent, self);
        }
      }
      else if (root_)
        root_->log(pLogEvent);
    }
  }

  void addAppender(LogAppender::ptr pAppender)
  {
    std::lock_guard<std::mutex> locker(mutex_);

    if (!pAppender->getFormatter()) {
      pAppender->setFormatter(pFormatter_);
    }
    appenders_.push_back(pAppender);
  }
  void removeAppender(LogAppender::ptr pAppender)
  {
    std::lock_guard<std::mutex> locker(mutex_);
    auto it = std::find(appenders_.begin(), appenders_.end(), pAppender);
    if (it != appenders_.end()) {
      appenders_.erase(it);
    }
  }
  void clearAppenders()
  {
    std::lock_guard<std::mutex> locker(mutex_);
    appenders_.clear();
  }

  LogLevel::Level getLevel() const { return level_; }
  void setLevel(LogLevel::Level level) { level_ = level; }

  const std::string &getName() const { return name_; }
  void setFormatter(LogFormatter::ptr pFormatter)
  {
    std::lock_guard<std::mutex> locker(mutex_);
    pFormatter_ = pFormatter;
  }
  void setFormatter(const std::string &pattern)
  {
    std::lock_guard<std::mutex> locker(mutex_);
    pFormatter_ = std::make_shared<LogFormatter>(pattern);
  }
  LogFormatter::ptr getFormatter()
  {
    std::lock_guard<std::mutex> locker(mutex_);
    return pFormatter_;
  }

  Logger::ptr getLogger() { return root_; }
  void setLogger(Logger::ptr pLogger) { root_ = pLogger; }
private:
  /// 日志名称
  std::string name_;
  /// 日志级别
  LogLevel::Level level_{LogLevel::Level::LDEBUG};
  /// Mutex
  std::mutex mutex_;
  /// 日志目标集合
  std::list<LogAppender::ptr> appenders_;
  /// 日志格式器
  LogFormatter::ptr pFormatter_;
  /// 主日志器
  Logger::ptr root_;
};

/// LogFormatterItems
inline void LogFormatter::MessageFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  os << pLogEvent->getContent();
}
inline void LogFormatter::LogLevelFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  if (pLogEvent->isLogColorOn()) {
    LogColorConfig conf = pLogEvent->getColorConfig();
    switch (pLogEvent->getLevel()) {
    case LogLevel::LDEBUG:
      os << conf.getColor(conf.LOG_LEVEL_DEBUG);
      break;
    case LogLevel::LINFO:
      os << conf.getColor(conf.LOG_LEVEL_INFO);
      break;
    case LogLevel::LWARN:
      os << conf.getColor(conf.LOG_LEVEL_WARN);
      break;
    case LogLevel::LERROR:
      os << conf.getColor(conf.LOG_LEVEL_ERROR);
      break;
    case LogLevel::LFATAL:
      os << conf.getColor(conf.LOG_LEVEL_FATAL);
      break;
    }
    os << LogLevel::toString(pLogEvent->getLevel());
    if (pLogEvent->getLevel() != LogLevel::LUNKNOWN)
      os << conf.getColor(conf.LOG_END);
  }
  else {
    os << LogLevel::toString(pLogEvent->getLevel());
  }
}
inline void LogFormatter::LogNameFormatterItem::format(std::ostream &os, LogEvent::ptr pLogEvent,
                                                       std::shared_ptr<Logger> pLogger) {
  os << pLogger->getName();
}
inline void LogFormatter::DateTimeFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  auto timestamp = pLogEvent->getTimestamp();
  auto tp = std::chrono::time_point<std::chrono::system_clock>(std::chrono::milliseconds(timestamp));
  std::time_t time = std::chrono::system_clock::to_time_t(tp);
  struct tm tm = *std::localtime(&time);
  char buf[64];
  std::strftime(buf, sizeof(buf), timefmt_.c_str(), &tm);
  os << buf;
}
inline void LogFormatter::FilenameFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  os << pLogEvent->getFilename();
}
inline void LogFormatter::LineFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  os << pLogEvent->getLine();
}
inline void LogFormatter::StringFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  os << str_;
}
inline void LogFormatter::CharFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  os << str_;
}
inline void LogFormatter::FunctionNameFormatterItem::format(std::ostream& os, LogEvent::ptr pLogEvent,
  std::shared_ptr<Logger> pLogger) {
  os << pLogEvent->getFunctionName();
}

class LogEventWrapper {
public:
  using ptr = std::shared_ptr<LogEventWrapper>;

  /**
   * @brief 构造函数
   * @param[in] pEvent  日志事件
   * @param[in] pLogger 日志器
   */
  LogEventWrapper(LogEvent::ptr pEvent, Logger::ptr pLogger) :
    pEvent_(pEvent), pLogger_(pLogger)
  {}
  ~LogEventWrapper()
  {
    pLogger_->log(pEvent_);
  }

  LogEvent::ptr getEvent() const { return pEvent_; }
  Logger::ptr getLogger() const { return pLogger_; }
  std::stringstream &getSS() { return pEvent_->getSS(); }
private:
  ///日志事件
  LogEvent::ptr pEvent_;
  Logger::ptr pLogger_;
};

class LogManager
{
public:
  using ptr = std::shared_ptr<LogManager>;

  static LogManager *instance()
  {
    static LogManager *manager = new LogManager();
    return manager;
  }

  LogManager()
  {
    root_.reset(new Logger());
    auto pAppender = std::make_shared<StdoutLogAppender>();
    // pAppender->setFormatter(root_->getFormatter());
    root_->addAppender(pAppender);

    loggers_[root_->getName()] = root_;

    init();
  }
  ~LogManager() = default;
  /**
   * @brief 获取日志器
   * @param[in] name 日志器名称
   */
  Logger::ptr getLogger(const std::string &name)
  {
    std::lock_guard<std::mutex> locker(mutex_);
    auto it = loggers_.find(name);
    if (it != loggers_.end()) {
      return it->second;
    }

    auto pLogger = std::make_shared<Logger>(name);
    pLogger->setLogger(root_);
    loggers_[name] = pLogger;
    return pLogger;
  }

  // TODO: For future do
  void init() {}
  Logger::ptr getRoot() const { return root_; }
private:
  /// Mutex
  std::mutex mutex_;
  /// 日志器容器
  std::unordered_map<std::string, Logger::ptr> loggers_;
  /// 主日志器
  Logger::ptr root_;
};

class LogIniter
{
public:
  /* the appender's formatter is the same as the logger */
  static Logger::ptr getLogger(
    /* logger */
    const std::string &log_name, LogLevel::Level log_level,
    /* formatter */
    const std::string &format_pattern = kDefaultFormatPattern,
    /* appender */
    bool write2file = true, const std::string &filename = "x")
  {
    auto pLogger = GET_LOGGER(log_name);
    pLogger->setLevel(log_level);
    if (format_pattern != kDefaultFormatPattern)
      pLogger->setFormatter(format_pattern);

    if (write2file) {
      pLogger->addAppender(std::make_shared<FileLogAppender>(filename));
    }
    else {
      pLogger->addAppender(std::make_shared<StdoutLogAppender>());
    }

    return pLogger;
  }
private:
};

/* LogIniter::getLogger("sample", "LogLevel::Level::LDEBUG",
 *                      kDefaultFormatPattern, true,
 *                      "sample")
 *
 * sample_${DATE}_${Count}.log
 */
