/*
 * Copyright (c) 2011, JANET(UK)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of JANET(UK) nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * JSON object wrapper with not-entirely-toll-free DDF bridging.
 */

#ifndef _UTIL_JSON_H_
#define _UTIL_JSON_H_ 1

#ifdef __cplusplus
#include <string>
#include <new>

#include <jansson.h>

#ifdef HAVE_SHIBRESOLVER
#include <shibsp/remoting/ddf.h>
using namespace shibsp;
#endif

namespace gss_bid_util {
    class JSONObject;

    class JSONException : public std::exception {
    public:
        JSONException(json_t *obj = NULL, json_type type = JSON_NULL);

        ~JSONException(void) throw() {
            json_decref(m_obj);
        }

        virtual const char *what(void) const throw() {
            return m_reason.c_str();
        }

    private:
        json_t *m_obj;
        json_type m_type;
        std::string m_reason;
    };

    class JSONIterator {
    public:
        JSONIterator(const JSONObject &obj);
        ~JSONIterator(void);
        const char *key(void) const;
        JSONObject value(void) const;
        bool next(void);

    private:
        json_t *m_obj;
        void *m_iter;
    };

    class JSONObject {
    public:
        static JSONObject load(const char *input, size_t flags, json_error_t *error);
        static JSONObject load(FILE *, size_t flags, json_error_t *error);

        static JSONObject object(void);
        static JSONObject array(void);
        static JSONObject null(void);
#ifdef HAVE_SHIBRESOLVER
        static JSONObject ddf(DDF &value);
#endif

        char *dump(size_t flags = 0) const;
        void dump(FILE *fp, size_t flags = JSON_INDENT(4)) const;

        json_type type(void) const { return json_typeof(m_obj); }
        size_t size(void) const;

        JSONObject(void);
        JSONObject(const char *value);
        JSONObject(json_int_t value);
        JSONObject(double value);
        JSONObject(bool value);

        void set(const char *key, JSONObject &value);
        void set(const char *key, const char *value);
        void set(const char *key, json_int_t value);
        void del(const char *key);
        void update(JSONObject &value);
        JSONIterator iterator(void) const { return JSONIterator(*this); }
        JSONObject get(const char *key) const;
        JSONObject operator[](const char *key) const;

        JSONObject get(size_t index) const;
        JSONObject operator[](size_t index) const;
        void append(JSONObject &value);
        void insert(size_t index, JSONObject &value);
        void remove(size_t index);
        void clear(void);
        void extend(JSONObject &value);

        const gss_buffer_desc buffer(void) const;
        const char *string(void) const;
        json_int_t integer(void) const;
        double real(void) const;
        double number(void) const;
        bool boolean(void) const;
#ifdef HAVE_SHIBRESOLVER
        DDF ddf(void) const;
#endif

        bool isObject(void) const;
        bool isArray(void) const;
        bool isString(void) const;
        bool isInteger(void) const;
        bool isNumber(void) const;
        bool isBoolean(void) const;
        bool isNull(void) const;

        ~JSONObject(void)
        {
            if (m_obj != NULL)
                json_decref(m_obj);
        }

        JSONObject(const JSONObject &obj)
        {
            m_obj = json_incref(obj.m_obj);
        }

        JSONObject& operator=(const JSONObject &obj)
        {
            if (this != &obj)
                set(obj.m_obj);
            return *this;
        }

        JSONObject(json_t *obj, bool retain = true);

        json_t *get(void) const {
            return json_incref(m_obj);
        }

    private:
        friend class JSONIterator;

        void set(json_t *obj) {
            if (m_obj != obj) {
                json_decref(m_obj);
                m_obj = json_incref(m_obj);
            }
        }

        json_t *m_obj;
    };
}

#endif /* __cplusplus */

#endif /* _UTIL_JSON_H_ */
