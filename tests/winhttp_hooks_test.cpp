#include <gtest/gtest.h>
#include <windows.h>
#include <winhttp.h>

// This test case is designed to be run with the injector.
// The injector will load ai_hook.dll, which will hook WinHttpSendRequest.
// We can't easily check the debug output here, so this is more of a manual test.
// To verify, run this test under a debugger and check the debug output for our log messages.

TEST(WinHttpHookTest, MakesHttpRequest) {
    // This test is only meaningful if the ai_hook.dll has been injected.
    // We check if the module is loaded. If not, we pass the test with a note.
    HMODULE hMod = GetModuleHandleW(L"ai_hook.dll");
    if (hMod == NULL) {
        GTEST_SKIP() << "ai_hook.dll not injected, skipping test.";
        return;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL, 
               hConnect = NULL,
               hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen( L"WinHTTP Example/1.0",  
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                            WINHTTP_NO_PROXY_NAME, 
                            WINHTTP_NO_PROXY_BYPASS, 0 );

    // Specify an HTTP server.
    if( hSession )
        hConnect = WinHttpConnect( hSession, L"www.microsoft.com",
                                   INTERNET_DEFAULT_HTTPS_PORT, 0 );

    // Create an HTTP request handle.
    if( hConnect )
        hRequest = WinHttpOpenRequest( hConnect, L"GET", NULL,
                                       NULL, WINHTTP_NO_REFERER, 
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                       WINHTTP_FLAG_SECURE );

    // Send a request.
    if( hRequest )
        bResults = WinHttpSendRequest( hRequest, 
                                       WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );

    // End the request.
    if( bResults )
        bResults = WinHttpReceiveResponse( hRequest, NULL );

    // Keep reading data until there is nothing left.
    if( bResults )
    {
        do 
        {
            // Check for available data.
            dwSize = 0;
            if( !WinHttpQueryDataAvailable( hRequest, &dwSize ) )
                printf( "Error %u in WinHttpQueryDataAvailable.\n", GetLastError( ) );

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize+1];
            if( !pszOutBuffer )
            {
                printf( "Out of memory\n" );
                dwSize=0;
            }
            else
            {
                // Read the data.
                ZeroMemory( pszOutBuffer, dwSize+1 );

                if( !WinHttpReadData( hRequest, (LPVOID)pszOutBuffer, 
                                      dwSize, &dwDownloaded ) )
                    printf( "Error %u in WinHttpReadData.\n", GetLastError( ) );
                else
                    // For this test, we don't need to do anything with the data.
                    // We just want to trigger the hook.
                    ASSERT_GT(dwDownloaded, 0);

                // Free the memory allocated for the buffer.
                delete [] pszOutBuffer;
            }

        } while( dwSize > 0 );
    }


    // Report any errors.
    if( !bResults )
        printf( "Error %d has occurred.\n", GetLastError( ) );

    // Close any open handles.
    if( hRequest ) WinHttpCloseHandle( hRequest );
    if( hConnect ) WinHttpCloseHandle( hConnect );
    if( hSession ) WinHttpCloseHandle( hSession );

    ASSERT_TRUE(bResults);
}
