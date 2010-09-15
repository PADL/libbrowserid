/*
 *  Copyright 2010 Project Moonshot
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file shibresolver/resolver.h
 *
 * An embeddable component interface to Shibboleth SP attribute processing.
 */

#ifndef __shibresolver_h__
#define __shibresolver_h__

#if 0
#include <shibresolver/base.h>
#else
#define SHIBRESOLVER_API SHIBSP_API
#endif

#include <string>
#include <vector>

namespace xmltooling {
    class XMLTOOL_API XMLObject;
};

namespace opensaml {
    namespace saml2 {
        class SAML_API Assertion;
        class SAML_API NameID;
    };
};

namespace shibsp {
    class SHIBSP_API Attribute;
};

namespace shibresolver {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    /**
     * An embeddable component interface to Shibboleth SP attribute processing.
     */
    class SHIBRESOLVER_API ShibbolethResolver
    {
        MAKE_NONCOPYABLE(ShibbolethResolver);
    protected:
        ShibbolethResolver() {}
    public:
        ~ShibbolethResolver() {}

        /**
         * Sets the application ID to use for resolution.
         *
         * @param appID identifies an application in the SP configuration
         */
        void setApplicationID(const char* appID) {}

        /**
         * Sets the identity issuer to use for resolution.
         *
         * @param issuer    entityID of the identity "source", if known
         */
        void setIssuer(const char* issuer) {}

        /**
         * Adds a SAML token as input to the resolver.
         * <p>The caller retains ownership of the object.
         *
         * @param token an input token to evaluate
         */
        void addToken(
#ifdef SHIBSP_LITE
            const xmltooling::XMLObject* token
#else
            const opensaml::saml2::Assertion* token
#endif
            ) {}

        /**
         * Adds an Attribute as input to the resolver.
         * <p>The caller retains ownership of the object, but it MAY be modified
         * during the resolution process.
         *
         * @param attr  an input attribute
         */
        void addAttribute(shibsp::Attribute* attr) {}

        /**
         * Resolves attributes and returns them in the supplied array.
         * <p>The caller is responsible for freeing them.
         *
         * @param attrs array to populate
         */
        void resolveAttributes(std::vector<shibsp::Attribute*>& attrs) {}

        /**
         * Initializes SP runtime objects based on an XML configuration string or a configuration pathname.
         * <p>Each process using the library MUST call this function exactly once before using any library classes.
         *
         * @param config    a snippet of XML to parse (it <strong>MUST</strong> contain a type attribute) or a pathname
         * @param rethrow   true iff caught exceptions should be rethrown instead of just returning the status
         * @return true iff initialization was successful
         */
        static bool init(const char* config=NULL, bool rethrow=false) { return true; }

        /**
         * Shuts down runtime.
         *
         * Each process using the library SHOULD call this function exactly once before terminating itself.
         */
        static void term() {}

        /**
         * Returns a ShibbolethResolver instance.
         *
         * @return  a ShibbolethResolver instance, must be freed by the caller.
         */
        static ShibbolethResolver* create() { return new ShibbolethResolver(); }

    protected:
        /** Application ID. */
        std::string m_appID;

        /** Source of identity, if known. */
        std::string m_issuer;

        /** Input tokens. */
#ifdef SHIBSP_LITE
        std::vector<const xmltooling::XMLObject*> m_tokens;
#else
        std::vector<const opensaml::saml2::Assertion*> m_tokens;
#endif
        /** Input attributes. */
        std::vector<shibsp::Attribute*> m_attributes;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibresolver_h__ */
