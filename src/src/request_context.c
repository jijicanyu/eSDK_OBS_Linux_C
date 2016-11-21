/** **************************************************************************
 * request_context.c
 * 
 * Copyright 2008 Bryan Ischo <bryan@ischo.com>
 * 
 * This file is part of libs3.
 * 
 * libs3 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, version 3 of the License.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of this library and its programs with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * libs3 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * version 3 along with libs3, in a file named COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 ************************************************************************** **/

#include <curl/curl.h>
#include <stdlib.h>
#include <sys/select.h>
#include "request.h"
#include "request_context.h"
#include "securec.h"


#ifdef WIN32
# pragma warning (disable:4127)
#endif
//lint -e26 -e31 -e63 -e64 -e78 -e101 -e119 -e129 -e144 -e156 -e438 -e505 -e515 -e516 -e522 -e529 -e530 -e533 -e534 -e546 -e551 -e578 -e601
S3Status S3_create_request_context(S3RequestContext **requestContextReturn)
{
    *requestContextReturn = 
        (S3RequestContext *) malloc(sizeof(S3RequestContext));
    
    if (!*requestContextReturn) {
        return S3StatusOutOfMemory;
    }

	memset_s(*requestContextReturn, sizeof(S3RequestContext), 0, sizeof(S3RequestContext));
    
    if (((*requestContextReturn)->curlm = curl_multi_init()) ==NULL) {
        free(*requestContextReturn);
		*requestContextReturn = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
        return S3StatusOutOfMemory;
    }

    (*requestContextReturn)->requests = 0;

    return S3StatusOK;
}


void S3_destroy_request_context(S3RequestContext *requestContext)
{
    curl_multi_cleanup(requestContext->curlm);

    // For each request in the context, call back its done method with
    // 'interrupted' status
    Request *r = requestContext->requests, *rFirst = r;
    
    if (r) do {
        r->status = S3StatusInterrupted;
        Request *rNext = r->next;
        request_finish(r);
        r = rNext;
    } while (r != rFirst);

    free(requestContext);
	requestContext = NULL;//zwx367245 2016.10.19 Set a pointer NULL after free();
}

//lint -e550
S3Status S3_runall_request_context(S3RequestContext *requestContext)
{
    int requestsRemaining = 0;
    do {
		fd_set readfds, writefds, exceptfds;//lint !e42 Initialized value by jwx329074 2016.11.16
        //FD_ZERO(&readfds);
        //FD_ZERO(&writefds);
        //FD_ZERO(&exceptfds);
		memset_s(&readfds, sizeof(readfds), 0, sizeof(readfds));
		memset_s(&writefds, sizeof(writefds), 0, sizeof(writefds));
		memset_s(&exceptfds, sizeof(exceptfds), 0, sizeof(exceptfds));
		
        int maxfd = 0;
        S3Status status = S3_get_request_context_fdsets
            (requestContext, &readfds, &writefds, &exceptfds, &maxfd);
        if (status != S3StatusOK) {
            return status;
        }
		
        // curl will return -1 if it hasn't even created any fds yet because
        // none of the connections have started yet.  In this case, don't
        // do the select at all, because it will wait forever; instead, just
        // skip it and go straight to running the underlying CURL handles
        if (maxfd != -1) {
            int64_t timeout = S3_get_request_context_timeout(requestContext);
            struct timeval tv = { (long)timeout / 1000, ((long)timeout % 1000) * 1000 };//lint !e121 !e565

			//cheack return value from library by jwx329074 2016.11.16
            int selectResult = select(maxfd + 1, &readfds, &writefds, &exceptfds,(timeout == -1) ? 0 : &tv);
			switch(selectResult)
			{
				case 0:
					COMMLOG(OBS_LOGERROR, "select timeout!");
					break;

				case -1:
					COMMLOG(OBS_LOGERROR, "select error!");
					break;
				default:
					break;
			}

        }
        status = S3_runonce_request_context(requestContext, &requestsRemaining);//lint !e506
        if (status != S3StatusOK) {
            return status;
        }
    } while (requestsRemaining);
    
    return S3StatusOK;
}
//lint +e550


S3Status S3_runonce_request_context(S3RequestContext *requestContext, 
                                    int *requestsRemainingReturn)
{
    CURLMcode status = CURLM_OK;

    do {
        status = curl_multi_perform(requestContext->curlm,
                                    requestsRemainingReturn);
		//lint -e30 -e142
        switch (status) {
        case CURLM_OK:
        case CURLM_CALL_MULTI_PERFORM:
            break;
        case CURLM_OUT_OF_MEMORY:
            return S3StatusOutOfMemory;
        default:
            return S3StatusInternalError;
        }
		//lint +e30 +e142
        CURLMsg *msg = NULL;
        int junk = 0;
        while ((msg = curl_multi_info_read(requestContext->curlm, &junk)) != NULL) {
            if (msg->msg != CURLMSG_DONE) {
                return S3StatusInternalError;
            }
            Request *request = NULL;
            if (curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, 
                                  (char **) (char *) &request) != CURLE_OK) {
                return S3StatusInternalError;
            }
            // Remove the request from the list of requests
            if (request->prev == request->next) {
                // It was the only one on the list
                requestContext->requests = 0;
            }
            else {
                // It doesn't matter what the order of them are, so just in
                // case request was at the head of the list, put the one after
                // request to the head of the list
                requestContext->requests = request->next;
                request->prev->next = request->next;
                request->next->prev = request->prev;
            }
            if ((msg->data.result != CURLE_OK) &&
                (request->status == S3StatusOK)) {
                request->status = request_curl_code_to_status
                    (msg->data.result);
            }
            if (curl_multi_remove_handle(requestContext->curlm, 
                                         msg->easy_handle) != CURLM_OK) {
                return S3StatusInternalError;
            }
            // Finish the request, ensuring that all callbacks have been made,
            // and also releases the request
            request_finish(request);
            // Now, since a callback was made, there may be new requests 
            // queued up to be performed immediately, so do so
            status = CURLM_CALL_MULTI_PERFORM;
        }
    } while (status == CURLM_CALL_MULTI_PERFORM);

    return S3StatusOK;
}

S3Status S3_get_request_context_fdsets(S3RequestContext *requestContext,
                                       fd_set *readFdSet, fd_set *writeFdSet,
                                       fd_set *exceptFdSet, int *maxFd)
{
    return ((curl_multi_fdset(requestContext->curlm, readFdSet, writeFdSet,
                              exceptFdSet, maxFd) == CURLM_OK) ?
            S3StatusOK : S3StatusInternalError);
}

int64_t S3_get_request_context_timeout(S3RequestContext *requestContext)
{
    long timeout = 0;

    if (curl_multi_timeout(requestContext->curlm, &timeout) != CURLM_OK) {
        timeout = 0;
    }
    
    return timeout;
}
//lint +e26 +e31 +e63 +e64 +e78 +e101 +e119 +e129 +e144 +e156 +e438 +e505 +e516 +e515 +e522 +e529 +e530 +e533 +e534 +e546 +e551 +e578 +e601