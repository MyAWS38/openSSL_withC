

<!DOCTYPE html>
<html lang="en">
  <head>
      <meta charset="utf-8">
      <title>OpenSSL Certificate Parsing</title>
      <meta name="description" content="A guide to parsing and validating X.509 digital certificates using OpenSSL based on our experiences performing scans of the HTTPS ecosystem.">
      
      <meta name="author" content="Zakir Durumeric">
      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
	  <link href="https://fonts.googleapis.com/css?family=Fira+Sans:300,400,500,600,700" rel="stylesheet">
  	<link href="/assets/themes/zakird.com/css/style.css" rel="stylesheet" type="text/css">
  	<link href="/assets/themes/zakird.com/css/pygments.css" rel="stylesheet" type="text/css">
  </head>
  <body>
    <div class="container">
      <div class="row top">
        <div class="col-lg-offset-2 col-lg-8 col-md-offset-1 col-md-10 col-sm-12">
          

<div class="content post">
  <h1>Parsing X.509 Certificates with OpenSSL and C</h1>
  <span class="meta"><p><a href="/">Zakir Durumeric</a> | October 13, 2013</p></span>
  
<p>While <a href="https://www.openssl.org/">OpenSSL</a> has become one of the defacto
libraries for performing SSL and TLS operations, the library is surprisingly
opaque and its documentation is, at times, abysmal. As part of our recent
research, we have been performing Internet-wide scans of HTTPS hosts in order to
better understand the HTTPS ecosystem (<a href="https://jhalderm.com/pub/papers/https-imc13.pdf">Analysis of the HTTPS Certificate
Ecosystem</a>, <a href="https://zmap.io">ZMap: Fast
Internet-Wide Scanning and its Security Applications</a>). We use
OpenSSL for many of these operations including parsing X.509 certificates.
However, in order to parse and validate certificates, our team had to dig
through parts of the OpenSSL code base and multiple sources of documention to
find the correct functions to parse each piece of data. This post is intended to
document many of these operations in a single location in order to hopefully
alleviate this painful process for others.</p>

<p>If you have found other pieces of code particularly helpful, please don’t
hesitate to <a href="mailto:zakir@umich.edu">send them along</a> and we’ll update the post.
I want to note that if you’re starting to develop against OpenSSL, O’Reilly’s
<a href="http://www.amazon.com/Network-Security-OpenSSL-John-Viega/dp/059600270X"><em>Network Security with
OpenSSL</em></a>
is an incredibly helpful resource; the book contains many snippets and pieces of
documentation that I was not able to find anywhere online. I also want to thank
<a href="https://jdkasten.com/">James Kasten</a> who helped find and document several of
these solutions.</p>

<h2 id="creating-an-openssl-x509-object">Creating an OpenSSL X509 Object</h2>

<p>All of the operations we discuss start with either a single X.509 certificate or
a “stack” of certificates. OpenSSL represents a single certificate with an
<code class="highlighter-rouge">X509</code> struct and a list of certificates, such as the certificate chain
presented during a TLS handshake as a <code class="highlighter-rouge">STACK_OF(X509)</code>. Given that the parsing
and validation stems from here, it only seems reasonable to start with how to
create or access an X509 object. A few common scenarios are:</p>

<h3 id="1-you-have-initiated-an-ssl-or-tls-connection-using-openssl">1. You have initiated an SSL or TLS connection using OpenSSL.</h3>

<p>In this case, you have access to an OpenSSL <code class="highlighter-rouge">SSL</code> struct from which you can
extract the presented certificate as well as the entire certificate chain that
the server presented to the client. In our specific case, we use libevent to
perform TLS connections and can access the SSL struct from the libevent
bufferevent: <code class="highlighter-rouge">SSL *ssl = bufferevent_openssl_get_ssl(bev)</code>. This will clearly be
different depending on how you complete your connection. However, once you have
your SSL context, the server certificate and presented chain can be extracted as
follows:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#include &lt;openssl/x509.h&gt;
#include &lt;openssl/x509v3.h&gt;
</span>
<span class="n">X509</span> <span class="o">*</span><span class="n">cert</span> <span class="o">=</span> <span class="n">SSL_get_peer_certificate</span><span class="p">(</span><span class="n">ssl</span><span class="p">);</span>
<span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509</span><span class="p">)</span> <span class="o">*</span><span class="n">sk</span> <span class="o">=</span> <span class="n">SSL_get_peer_cert_chain</span><span class="p">(</span><span class="n">ssl</span><span class="p">);</span></code></pre></figure>

<p>We have found that at times, OpenSSL will produce an empty certificate chain
(<code class="highlighter-rouge">SSL_get_peer_cert_chain</code> will come back <code class="highlighter-rouge">NULL</code>) even though a client
certificate has been presented (the server certificate is generally presented as
the first certificate in the stack along with the remaining chain). It’s unclear
to us why this happens, but it’s not a deal breaker, as it’s easy to create a
new stack of certificates:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">X509</span> <span class="o">*</span><span class="n">cert</span> <span class="o">=</span> <span class="n">SSL_get_peer_certificate</span><span class="p">(</span><span class="n">ssl</span><span class="p">);</span>
<span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509</span><span class="p">)</span> <span class="o">*</span><span class="n">sk</span> <span class="o">=</span> <span class="n">sk_X509_new_null</span><span class="p">();</span>
<span class="n">sk_X509_push</span><span class="p">(</span><span class="n">sk</span><span class="p">,</span> <span class="n">cert</span><span class="p">);</span></code></pre></figure>

<h3 id="2-you-have-stored-a-certificate-on-disk-as-a-pem-file">2. You have stored a certificate on disk as a PEM file.</h3>
<p>For reference, a PEM file is the Base64-encoded version of an X.509 certificate, which should look similar to the following:</p>

<div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>-----BEGIN CERTIFICATE-----
MIIHIDCCBgigAwIBAgIIMrM8cLO76sYwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
iftrJvzAOMAPY5b/klZvqH6Ddubg/hUVPkiv4mr5MfWfglCQdFF1EBGNoZSFAU7y
ZkGENAvDmv+5xVCZELeiWA2PoNV4m/SW6NHrF7gz4MwQssqP9dGMbKPOF/D2nxic
TnD5WkGMCWpLgqDWWRoOrt6xf0BPWukQBDMHULlZgXzNtoGlEnwztLlnf0I/WWIS
eBSyDTeFJfopvoqXuws23X486fdKcCAV1n/Nl6y2z+uVvcyTRxY2/jegmV0n0kHf
gfcKzw==
-----END CERTIFICATE-----
</code></pre></div></div>

<p>In this case, you can access the certificate as follows:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#include &lt;stdio.h&gt;
#include &lt;openssl/x509.h&gt;
#include &lt;openssl/x509v3.h&gt;
</span>
<span class="kt">FILE</span> <span class="o">*</span><span class="n">fp</span> <span class="o">=</span> <span class="n">fopen</span><span class="p">(</span><span class="n">path</span><span class="p">,</span> <span class="s">"r"</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">fp</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to open: %s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">path</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="n">X509</span> <span class="o">*</span><span class="n">cert</span> <span class="o">=</span> <span class="n">PEM_read_X509</span><span class="p">(</span><span class="n">fp</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">cert</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to parse certificate in: %s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">path</span><span class="p">);</span>
	<span class="n">fclose</span><span class="p">(</span><span class="n">fp</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="c1">// any additional processing would go here..
</span>
<span class="n">X509_free</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span>
<span class="n">fclose</span><span class="p">(</span><span class="n">fp</span><span class="p">);</span></code></pre></figure>

<h3 id="3-you-have-access-to-the-raw-certificate-in-memory">3. You have access to the raw certificate in memory.</h3>

<p>In the case that you have access to the raw encoding of the certificate in
memory, you can parse it as follows. This is useful if you have stored raw
certificates in a database or similar data store.</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#include &lt;openssl/x509.h&gt;
#include &lt;openssl/x509v3.h&gt;
#include &lt;openssl/bio.h&gt;
</span>
<span class="k">const</span> <span class="kt">unsigned</span> <span class="kt">char</span> <span class="o">*</span><span class="n">data</span> <span class="o">=</span> <span class="p">...</span> <span class="p">;</span>
<span class="kt">size_t</span> <span class="n">len</span> <span class="o">=</span> <span class="p">...</span> <span class="p">;</span>

<span class="n">X509</span> <span class="o">*</span><span class="n">cert</span> <span class="o">=</span> <span class="n">d2i_X509</span><span class="p">(</span><span class="nb">NULL</span><span class="p">,</span> <span class="o">&amp;</span><span class="n">data</span><span class="p">,</span> <span class="n">len</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">cert</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to parse certificate in memory</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="c1">// any additional processing would go here..
</span>
<span class="n">X509_free</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span></code></pre></figure>

<h3 id="4-you-have-access-to-the-base64-encoded-pem-in-memory">4. You have access to the Base64 encoded PEM in memory.</h3>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">char</span><span class="o">*</span> <span class="n">pemCertString</span> <span class="o">=</span> <span class="p">.....</span> <span class="p">(</span><span class="n">includes</span> <span class="s">"-----BEGIN/END CERTIFICATE-----"</span><span class="p">)</span>
<span class="kt">size_t</span> <span class="n">certLen</span> <span class="o">=</span> <span class="n">strlen</span><span class="p">(</span><span class="n">pemCertString</span><span class="p">);</span>

<span class="n">BIO</span><span class="o">*</span> <span class="n">certBio</span> <span class="o">=</span> <span class="n">BIO_new</span><span class="p">(</span><span class="n">BIO_s_mem</span><span class="p">());</span>
<span class="n">BIO_write</span><span class="p">(</span><span class="n">certBio</span><span class="p">,</span> <span class="n">pemCertString</span><span class="p">,</span> <span class="n">certLen</span><span class="p">);</span>
<span class="n">X509</span><span class="o">*</span> <span class="n">certX509</span> <span class="o">=</span> <span class="n">PEM_read_bio_X509</span><span class="p">(</span><span class="n">certBio</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">certX509</span><span class="p">)</span> <span class="p">{</span>
    <span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to parse certificate in memory</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
    <span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="c1">// do stuff
</span>
<span class="n">BIO_free</span><span class="p">(</span><span class="n">certBio</span><span class="p">);</span>
<span class="n">X509_free</span><span class="p">(</span><span class="n">certX509</span><span class="p">);</span></code></pre></figure>

<h2 id="parsing-certificates">Parsing Certificates</h2>

<p>Now that we have access to a certificate in OpenSSL, we’ll focus on how to
extract useful data from the certificate. We don’t include the <code class="highlighter-rouge">#include</code>s in
every statement, but use the following headers throughout our codebase:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#include &lt;openssl/x509v3.h&gt;
#include &lt;openssl/bn.h&gt;
#include &lt;openssl/asn1.h&gt;
#include &lt;openssl/x509.h&gt;
#include &lt;openssl/x509_vfy.h&gt;
#include &lt;openssl/pem.h&gt;
#include &lt;openssl/bio.h&gt;
</span>
<span class="n">OpenSSL_add_all_algorithms</span><span class="p">();</span></code></pre></figure>

<p>You will also need the development versions of the OpenSSL libraries and to compile with <code class="highlighter-rouge">-lssl</code>.</p>

<h3 id="subject-and-issuer">Subject and Issuer</h3>

<p>The certificate subject and issuer can be easily extracted and represented as a
single string as follows:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">char</span> <span class="o">*</span><span class="n">subj</span> <span class="o">=</span> <span class="n">X509_NAME_oneline</span><span class="p">(</span><span class="n">X509_get_subject_name</span><span class="p">(</span><span class="n">cert</span><span class="p">),</span> <span class="nb">NULL</span><span class="p">,</span> <span class="mi">0</span><span class="p">);</span>
<span class="kt">char</span> <span class="o">*</span><span class="n">issuer</span> <span class="o">=</span> <span class="n">X509_NAME_oneline</span><span class="p">(</span><span class="n">X509_get_issuer_name</span><span class="p">(</span><span class="n">cert</span><span class="p">),</span> <span class="nb">NULL</span><span class="p">,</span> <span class="mi">0</span><span class="p">);</span></code></pre></figure>

<p>These can be freed by calling <code class="highlighter-rouge">OPENSSL_free</code>.</p>

<p>By default, the subject and issuer are returned in the following form:</p>

<div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>/C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.com
</code></pre></div></div>

<p>If you want to convert these into a more traditional looking DN, such as:</p>

<div class="highlighter-rouge"><div class="highlight"><pre class="highlight"><code>C=US, ST=Texas, L=Austin, O=Polycom Inc., OU=Video Division, CN=a.digitalnetbr.net
</code></pre></div></div>

<p>they can be converted with the following code:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">int</span> <span class="n">i</span><span class="p">,</span> <span class="n">curr_spot</span> <span class="o">=</span> <span class="mi">0</span><span class="p">;</span>
<span class="kt">char</span> <span class="o">*</span><span class="n">s</span> <span class="o">=</span> <span class="n">tmpBuf</span> <span class="o">+</span> <span class="mi">1</span><span class="p">;</span> <span class="cm">/* skip the first slash */</span>
<span class="kt">char</span> <span class="o">*</span><span class="n">c</span> <span class="o">=</span> <span class="n">s</span><span class="p">;</span>
<span class="k">while</span> <span class="p">(</span><span class="mi">1</span><span class="p">)</span> <span class="p">{</span>
	<span class="k">if</span> <span class="p">(((</span><span class="o">*</span><span class="n">s</span> <span class="o">==</span> <span class="sc">'/'</span><span class="p">)</span> <span class="o">&amp;&amp;</span> <span class="p">((</span><span class="n">s</span><span class="p">[</span><span class="mi">1</span><span class="p">]</span> <span class="o">&gt;=</span> <span class="sc">'A'</span><span class="p">)</span> <span class="o">&amp;&amp;</span> <span class="p">(</span><span class="n">s</span><span class="p">[</span><span class="mi">1</span><span class="p">]</span> <span class="o">&lt;=</span> <span class="sc">'Z'</span><span class="p">)</span> <span class="o">&amp;&amp;</span>
			<span class="p">((</span><span class="n">s</span><span class="p">[</span><span class="mi">2</span><span class="p">]</span> <span class="o">==</span> <span class="sc">'='</span><span class="p">)</span> <span class="o">||</span> <span class="p">((</span><span class="n">s</span><span class="p">[</span><span class="mi">2</span><span class="p">]</span> <span class="o">&gt;=</span> <span class="sc">'A'</span><span class="p">)</span> <span class="o">&amp;&amp;</span> <span class="p">(</span><span class="n">s</span><span class="p">[</span><span class="mi">2</span><span class="p">]</span> <span class="o">&lt;=</span> <span class="sc">'Z'</span><span class="p">)</span>
			<span class="o">&amp;&amp;</span> <span class="p">(</span><span class="n">s</span><span class="p">[</span><span class="mi">3</span><span class="p">]</span> <span class="o">==</span> <span class="sc">'='</span><span class="p">)))))</span> <span class="o">||</span> <span class="p">(</span><span class="o">*</span><span class="n">s</span> <span class="o">==</span> <span class="sc">'\0'</span><span class="p">))</span> <span class="p">{</span>
		<span class="n">i</span> <span class="o">=</span> <span class="n">s</span> <span class="o">-</span> <span class="n">c</span><span class="p">;</span>
		<span class="n">strncpy</span><span class="p">(</span><span class="n">destination</span> <span class="o">+</span> <span class="n">curr_spot</span><span class="p">,</span> <span class="n">c</span><span class="p">,</span> <span class="n">i</span><span class="p">);</span>
		<span class="n">curr_spot</span> <span class="o">+=</span> <span class="n">i</span><span class="p">;</span>
		<span class="n">assert</span><span class="p">(</span><span class="n">curr_spot</span> <span class="o">&lt;</span> <span class="n">size</span><span class="p">);</span>
		<span class="n">c</span> <span class="o">=</span> <span class="n">s</span> <span class="o">+</span> <span class="mi">1</span><span class="p">;</span> <span class="cm">/* skip following slash */</span>
		<span class="k">if</span> <span class="p">(</span><span class="o">*</span><span class="n">s</span> <span class="o">!=</span> <span class="sc">'\0'</span><span class="p">)</span> <span class="p">{</span>
			<span class="n">strncpy</span><span class="p">(</span><span class="n">destination</span> <span class="o">+</span> <span class="n">curr_spot</span><span class="p">,</span> <span class="s">", "</span><span class="p">,</span> <span class="mi">2</span><span class="p">);</span>
			<span class="n">curr_spot</span> <span class="o">+=</span> <span class="mi">2</span><span class="p">;</span>
		<span class="p">}</span>
	<span class="p">}</span>
	<span class="k">if</span> <span class="p">(</span><span class="o">*</span><span class="n">s</span> <span class="o">==</span> <span class="sc">'\0'</span><span class="p">)</span>
		<span class="k">break</span><span class="p">;</span>
	<span class="o">++</span><span class="n">s</span><span class="p">;</span>
<span class="p">}</span></code></pre></figure>

<p>It is also possible to extract particular elements from the subject. For example, the following code will iterate over all the values in the subject:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">X509_NAME</span> <span class="o">*</span><span class="n">subj</span> <span class="o">=</span> <span class="n">X509_get_subject_name</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span>

<span class="k">for</span> <span class="p">(</span><span class="kt">int</span> <span class="n">i</span> <span class="o">=</span> <span class="mi">0</span><span class="p">;</span> <span class="n">i</span> <span class="o">&lt;</span> <span class="n">X509_NAME_entry_count</span><span class="p">(</span><span class="n">subj</span><span class="p">);</span> <span class="n">i</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">X509_NAME_ENTRY</span> <span class="o">*</span><span class="n">e</span> <span class="o">=</span> <span class="n">X509_NAME_get_entry</span><span class="p">(</span><span class="n">subj</span><span class="p">,</span> <span class="n">i</span><span class="p">);</span>
	<span class="n">ASN1_STRING</span> <span class="o">*</span><span class="n">d</span> <span class="o">=</span> <span class="n">X509_NAME_ENTRY_get_data</span><span class="p">(</span><span class="n">e</span><span class="p">);</span>
	<span class="kt">char</span> <span class="o">*</span><span class="n">str</span> <span class="o">=</span> <span class="n">ASN1_STRING_data</span><span class="p">(</span><span class="n">d</span><span class="p">);</span>
<span class="p">}</span></code></pre></figure>

<p>or</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="k">for</span> <span class="p">(;;)</span> <span class="p">{</span>
    <span class="kt">int</span> <span class="n">lastpos</span> <span class="o">=</span> <span class="n">X509_NAME_get_index_by_NID</span><span class="p">(</span><span class="n">subj</span><span class="p">,</span> <span class="n">NID_commonName</span><span class="p">,</span> <span class="n">lastpos</span><span class="p">);</span>
    <span class="k">if</span> <span class="p">(</span><span class="n">lastpos</span> <span class="o">==</span> <span class="o">-</span><span class="mi">1</span><span class="p">)</span>
        <span class="k">break</span><span class="p">;</span>
    <span class="n">X509_NAME_ENTRY</span> <span class="o">*</span><span class="n">e</span> <span class="o">=</span> <span class="n">X509_NAME_get_entry</span><span class="p">(</span><span class="n">subj</span><span class="p">,</span> <span class="n">lastpos</span><span class="p">);</span>
    <span class="cm">/* Do something with e */</span>
<span class="p">}</span></code></pre></figure>

<h3 id="cryptographic-eg-sha-1-fingerprint">Cryptographic (e.g. SHA-1) Fingerprint</h3>

<p>We can calculate the SHA-1 fingerprint (or any other fingerprint) with the
following code:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#define SHA1LEN 20
</span><span class="kt">char</span> <span class="n">buf</span><span class="p">[</span><span class="n">SHA1LEN</span><span class="p">];</span>

<span class="k">const</span> <span class="n">EVP_MD</span> <span class="o">*</span><span class="n">digest</span> <span class="o">=</span> <span class="n">EVP_sha1</span><span class="p">();</span>
<span class="kt">unsigned</span> <span class="n">len</span><span class="p">;</span>

<span class="kt">int</span> <span class="n">rc</span> <span class="o">=</span> <span class="n">X509_digest</span><span class="p">(</span><span class="n">cert</span><span class="p">,</span> <span class="n">digest</span><span class="p">,</span> <span class="p">(</span><span class="kt">unsigned</span> <span class="kt">char</span><span class="o">*</span><span class="p">)</span> <span class="n">buf</span><span class="p">,</span> <span class="o">&amp;</span><span class="n">len</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="n">rc</span> <span class="o">==</span> <span class="mi">0</span> <span class="o">||</span> <span class="n">len</span> <span class="o">!=</span> <span class="n">SHA1LEN</span><span class="p">)</span> <span class="p">{</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>
<span class="k">return</span> <span class="n">EXIT_SUCCESS</span><span class="p">;</span></code></pre></figure>

<p>This will produce the raw fingerprint. This can be converted to the human
readable hex version as follows:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">void</span> <span class="nf">hex_encode</span><span class="p">(</span><span class="kt">unsigned</span> <span class="kt">char</span><span class="o">*</span> <span class="n">readbuf</span><span class="p">,</span> <span class="kt">void</span> <span class="o">*</span><span class="n">writebuf</span><span class="p">,</span> <span class="kt">size_t</span> <span class="n">len</span><span class="p">)</span>
<span class="p">{</span>
	<span class="k">for</span><span class="p">(</span><span class="kt">size_t</span> <span class="n">i</span><span class="o">=</span><span class="mi">0</span><span class="p">;</span> <span class="n">i</span> <span class="o">&lt;</span> <span class="n">len</span><span class="p">;</span> <span class="n">i</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>
		<span class="kt">char</span> <span class="o">*</span><span class="n">l</span> <span class="o">=</span> <span class="p">(</span><span class="kt">char</span><span class="o">*</span><span class="p">)</span> <span class="p">(</span><span class="mi">2</span><span class="o">*</span><span class="n">i</span> <span class="o">+</span> <span class="p">((</span><span class="kt">intptr_t</span><span class="p">)</span> <span class="n">writebuf</span><span class="p">));</span>
		<span class="n">sprintf</span><span class="p">(</span><span class="n">l</span><span class="p">,</span> <span class="s">"%02x"</span><span class="p">,</span> <span class="n">readbuf</span><span class="p">[</span><span class="n">i</span><span class="p">]);</span>
	<span class="p">}</span>
<span class="p">}</span>

<span class="kt">char</span> <span class="n">strbuf</span><span class="p">[</span><span class="mi">2</span><span class="o">*</span><span class="n">SHA1LEN</span><span class="o">+</span><span class="mi">1</span><span class="p">];</span>
<span class="n">hex_encode</span><span class="p">(</span><span class="n">buf</span><span class="p">,</span> <span class="n">strbuf</span><span class="p">,</span> <span class="n">SHA1LEN</span><span class="p">);</span></code></pre></figure>

<h3 id="version">Version</h3>

<p>Parsing the certificate version is straight-foward; the only oddity is that it
is zero-indexed:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">int</span> <span class="n">version</span> <span class="o">=</span> <span class="p">((</span><span class="kt">int</span><span class="p">)</span> <span class="n">X509_get_version</span><span class="p">(</span><span class="n">cert</span><span class="p">))</span> <span class="o">+</span> <span class="mi">1</span><span class="p">;</span></code></pre></figure>

<h3 id="serial-number">Serial Number</h3>

<p>Serial numbers can be arbitrarily large as well as positive or negative. As
such, we handle it as a string instead of a typical integer in our processing.</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#define SERIAL_NUM_LEN 1000;
</span><span class="kt">char</span> <span class="n">serial_number</span><span class="p">[</span><span class="n">SERIAL_NUM_LEN</span><span class="o">+</span><span class="mi">1</span><span class="p">];</span>

<span class="n">ASN1_INTEGER</span> <span class="o">*</span><span class="n">serial</span> <span class="o">=</span> <span class="n">X509_get_serialNumber</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span>

<span class="n">BIGNUM</span> <span class="o">*</span><span class="n">bn</span> <span class="o">=</span> <span class="n">ASN1_INTEGER_to_BN</span><span class="p">(</span><span class="n">serial</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">bn</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to convert ASN1INTEGER to BN</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="kt">char</span> <span class="o">*</span><span class="n">tmp</span> <span class="o">=</span> <span class="n">BN_bn2dec</span><span class="p">(</span><span class="n">bn</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">tmp</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to convert BN to decimal string.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="n">BN_free</span><span class="p">(</span><span class="n">bn</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="k">if</span> <span class="p">(</span><span class="n">strlen</span><span class="p">(</span><span class="n">tmp</span><span class="p">)</span> <span class="o">&gt;=</span> <span class="n">len</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"buffer length shorter than serial number</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="n">BN_free</span><span class="p">(</span><span class="n">bn</span><span class="p">);</span>
	<span class="n">OPENSSL_free</span><span class="p">(</span><span class="n">tmp</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="n">strncpy</span><span class="p">(</span><span class="n">buf</span><span class="p">,</span> <span class="n">tmp</span><span class="p">,</span> <span class="n">len</span><span class="p">);</span>
<span class="n">BN_free</span><span class="p">(</span><span class="n">bn</span><span class="p">);</span>
<span class="n">OPENSSL_free</span><span class="p">(</span><span class="n">tmp</span><span class="p">);</span></code></pre></figure>

<h3 id="signature-algorithm">Signature Algorithm</h3>

<p>The signature algorithm on a certificate is stored as an OpenSSSL NID:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">int</span> <span class="n">pkey_nid</span> <span class="o">=</span> <span class="n">OBJ_obj2nid</span><span class="p">(</span><span class="n">cert</span><span class="o">-&gt;</span><span class="n">cert_info</span><span class="o">-&gt;</span><span class="n">key</span><span class="o">-&gt;</span><span class="n">algor</span><span class="o">-&gt;</span><span class="n">algorithm</span><span class="p">);</span>

<span class="k">if</span> <span class="p">(</span><span class="n">pkey_nid</span> <span class="o">==</span> <span class="n">NID_undef</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to find specified signature algorithm name.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span></code></pre></figure>

<p>This can be translated into a string representation (either short name or long
description):</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">char</span> <span class="n">sigalgo_name</span><span class="p">[</span><span class="n">SIG_ALGO_LEN</span><span class="o">+</span><span class="mi">1</span><span class="p">];</span>
<span class="k">const</span> <span class="kt">char</span><span class="o">*</span> <span class="n">sslbuf</span> <span class="o">=</span> <span class="n">OBJ_nid2ln</span><span class="p">(</span><span class="n">pkey_nid</span><span class="p">);</span>

<span class="k">if</span> <span class="p">(</span><span class="n">strlen</span><span class="p">(</span><span class="n">sslbuf</span><span class="p">)</span> <span class="o">&gt;</span> <span class="n">PUBKEY_ALGO_LEN</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"public key algorithm name longer than allocated buffer.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="n">strncpy</span><span class="p">(</span><span class="n">buf</span><span class="p">,</span> <span class="n">sslbuf</span><span class="p">,</span> <span class="n">PUBKEY_ALGO_LEN</span><span class="p">);</span></code></pre></figure>

<p>This will result in a string such as <code class="highlighter-rouge">sha1WithRSAEncryption</code> or <code class="highlighter-rouge">md5WithRSAEncryption</code>.</p>

<h3 id="public-key">Public Key</h3>

<p>Parsing the public key on a certificate is type-specific. Here, we provide
information on how to extract which type of key is included and to parse RSA and
DSA keys:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">char</span> <span class="n">pubkey_algoname</span><span class="p">[</span><span class="n">PUBKEY_ALGO_LEN</span><span class="p">];</span>

<span class="kt">int</span> <span class="n">pubkey_algonid</span> <span class="o">=</span> <span class="n">OBJ_obj2nid</span><span class="p">(</span><span class="n">cert</span><span class="o">-&gt;</span><span class="n">cert_info</span><span class="o">-&gt;</span><span class="n">key</span><span class="o">-&gt;</span><span class="n">algor</span><span class="o">-&gt;</span><span class="n">algorithm</span><span class="p">);</span>

<span class="k">if</span> <span class="p">(</span><span class="n">pubkey_algonid</span> <span class="o">==</span> <span class="n">NID_undef</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to find specified public key algorithm name.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
<span class="p">}</span>

<span class="k">const</span> <span class="kt">char</span><span class="o">*</span> <span class="n">sslbuf</span> <span class="o">=</span> <span class="n">OBJ_nid2ln</span><span class="p">(</span><span class="n">pubkey_algonid</span><span class="p">);</span>
<span class="n">assert</span><span class="p">(</span><span class="n">strlen</span><span class="p">(</span><span class="n">sslbuf</span><span class="p">)</span> <span class="o">&lt;</span> <span class="n">PUBKEY_ALGO_LEN</span><span class="p">);</span>
<span class="n">strncpy</span><span class="p">(</span><span class="n">buf</span><span class="p">,</span> <span class="n">sslbuf</span><span class="p">,</span> <span class="n">PUBKEY_ALGO_LEN</span><span class="p">);</span>

<span class="k">if</span> <span class="p">(</span><span class="n">pubkey_algonid</span> <span class="o">==</span> <span class="n">NID_rsaEncryption</span> <span class="o">||</span> <span class="n">pubkey_algonid</span> <span class="o">==</span> <span class="n">NID_dsa</span><span class="p">)</span> <span class="p">{</span>

	<span class="n">EVP_PKEY</span> <span class="o">*</span><span class="n">pkey</span> <span class="o">=</span> <span class="n">X509_get_pubkey</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span>
	<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">pkey</span><span class="p">,</span> <span class="s">"unable to extract public key from certificate"</span><span class="p">);</span>

	<span class="n">RSA</span> <span class="o">*</span><span class="n">rsa_key</span><span class="p">;</span>
	<span class="n">DSA</span> <span class="o">*</span><span class="n">dsa_key</span><span class="p">;</span>
	<span class="kt">char</span> <span class="o">*</span><span class="n">rsa_e_dec</span><span class="p">,</span> <span class="o">*</span><span class="n">rsa_n_hex</span><span class="p">,</span> <span class="o">*</span><span class="n">dsa_p_hex</span><span class="p">,</span> <span class="o">*</span><span class="n">dsa_p_hex</span><span class="p">,</span>
			 <span class="o">*</span><span class="n">dsa_q_hex</span><span class="p">,</span> <span class="o">*</span><span class="n">dsa_g_hex</span><span class="p">,</span> <span class="o">*</span><span class="n">dsa_y_hex</span><span class="p">;</span>

	<span class="k">switch</span><span class="p">(</span><span class="n">pubkey_algonid</span><span class="p">)</span> <span class="p">{</span>

		<span class="k">case</span> <span class="n">NID_rsaEncryption</span><span class="p">:</span>

			<span class="n">rsa_key</span> <span class="o">=</span> <span class="n">pkey</span><span class="o">-&gt;</span><span class="n">pkey</span><span class="p">.</span><span class="n">rsa</span><span class="p">;</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">rsa_key</span><span class="p">,</span> <span class="s">"unable to extract RSA public key"</span><span class="p">);</span>

			<span class="n">rsa_e_dec</span> <span class="o">=</span> <span class="n">BN_bn2dec</span><span class="p">(</span><span class="n">rsa_key</span><span class="o">-&gt;</span><span class="n">e</span><span class="p">);</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">rsa_e_dec</span><span class="p">,</span>  <span class="s">"unable to extract rsa exponent"</span><span class="p">);</span>

			<span class="n">rsa_n_hex</span> <span class="o">=</span> <span class="n">BN_bn2hex</span><span class="p">(</span><span class="n">rsa_key</span><span class="o">-&gt;</span><span class="n">n</span><span class="p">);</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">rsa_n_hex</span><span class="p">,</span>  <span class="s">"unable to extract rsa modulus"</span><span class="p">);</span>

			<span class="k">break</span><span class="p">;</span>

		<span class="k">case</span> <span class="n">NID_dsa</span><span class="p">:</span>

			<span class="n">dsa_key</span> <span class="o">=</span> <span class="n">pkey</span><span class="o">-&gt;</span><span class="n">pkey</span><span class="p">.</span><span class="n">dsa</span><span class="p">;</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">dsa_key</span><span class="p">,</span> <span class="s">"unable to extract DSA pkey"</span><span class="p">);</span>

			<span class="n">dsa_p_hex</span> <span class="o">=</span> <span class="n">BN_bn2hex</span><span class="p">(</span><span class="n">dsa_key</span><span class="o">-&gt;</span><span class="n">p</span><span class="p">);</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">dsa_p_hex</span><span class="p">,</span> <span class="s">"unable to extract DSA p"</span><span class="p">);</span>

			<span class="n">dsa_q_hex</span> <span class="o">=</span> <span class="n">BN_bn2hex</span><span class="p">(</span><span class="n">dsa_key</span><span class="o">-&gt;</span><span class="n">q</span><span class="p">);</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">dsa_q_hex</span><span class="p">,</span> <span class="s">"unable to extract DSA q"</span><span class="p">);</span>

			<span class="n">dsa_g_hex</span> <span class="o">=</span> <span class="n">BN_bn2hex</span><span class="p">(</span><span class="n">dsa_key</span><span class="o">-&gt;</span><span class="n">g</span><span class="p">);</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">dsa_g_hex</span><span class="p">,</span> <span class="s">"unable to extract DSA g"</span><span class="p">);</span>

			<span class="n">dsa_y_hex</span> <span class="o">=</span> <span class="n">BN_bn2hex</span><span class="p">(</span><span class="n">dsa_key</span><span class="o">-&gt;</span><span class="n">pub_key</span><span class="p">);</span>
			<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">dsa_y_hex</span><span class="p">,</span> <span class="s">"unable to extract DSA y"</span><span class="p">);</span>

			<span class="k">break</span><span class="p">;</span>

		<span class="k">default</span><span class="o">:</span>
			<span class="k">break</span><span class="p">;</span>
	<span class="p">}</span>

	<span class="n">EVP_PKEY_free</span><span class="p">(</span><span class="n">pkey</span><span class="p">);</span>
<span class="p">}</span></code></pre></figure>

<h3 id="validity-period">Validity Period</h3>

<p>OpenSSL represents the not-valid-after (expiration) and not-valid-before as <code class="highlighter-rouge">ASN1_TIME</code> objects, which can be extracted as follows:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">ASN1_TIME</span> <span class="o">*</span><span class="n">not_before</span> <span class="o">=</span> <span class="n">X509_get_notBefore</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span>
<span class="n">ASN1_TIME</span> <span class="o">*</span><span class="n">not_after</span> <span class="o">=</span> <span class="n">X509_get_notAfter</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span></code></pre></figure>

<p>These can be converted into ISO-8601 timestamps using the following code:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#define DATE_LEN 128
</span>
<span class="kt">int</span> <span class="nf">convert_ASN1TIME</span><span class="p">(</span><span class="n">ASN1_TIME</span> <span class="o">*</span><span class="n">t</span><span class="p">,</span> <span class="kt">char</span><span class="o">*</span> <span class="n">buf</span><span class="p">,</span> <span class="kt">size_t</span> <span class="n">len</span><span class="p">)</span>
<span class="p">{</span>
	<span class="kt">int</span> <span class="n">rc</span><span class="p">;</span>
	<span class="n">BIO</span> <span class="o">*</span><span class="n">b</span> <span class="o">=</span> <span class="n">BIO_new</span><span class="p">(</span><span class="n">BIO_s_mem</span><span class="p">());</span>
	<span class="n">rc</span> <span class="o">=</span> <span class="n">ASN1_TIME_print</span><span class="p">(</span><span class="n">b</span><span class="p">,</span> <span class="n">t</span><span class="p">);</span>
	<span class="k">if</span> <span class="p">(</span><span class="n">rc</span> <span class="o">&lt;=</span> <span class="mi">0</span><span class="p">)</span> <span class="p">{</span>
		<span class="n">log_error</span><span class="p">(</span><span class="s">"fetchdaemon"</span><span class="p">,</span> <span class="s">"ASN1_TIME_print failed or wrote no data.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
		<span class="n">BIO_free</span><span class="p">(</span><span class="n">b</span><span class="p">);</span>
		<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
	<span class="p">}</span>
	<span class="n">rc</span> <span class="o">=</span> <span class="n">BIO_gets</span><span class="p">(</span><span class="n">b</span><span class="p">,</span> <span class="n">buf</span><span class="p">,</span> <span class="n">len</span><span class="p">);</span>
	<span class="k">if</span> <span class="p">(</span><span class="n">rc</span> <span class="o">&lt;=</span> <span class="mi">0</span><span class="p">)</span> <span class="p">{</span>
		<span class="n">log_error</span><span class="p">(</span><span class="s">"fetchdaemon"</span><span class="p">,</span> <span class="s">"BIO_gets call failed to transfer contents to buf"</span><span class="p">);</span>
		<span class="n">BIO_free</span><span class="p">(</span><span class="n">b</span><span class="p">);</span>
		<span class="k">return</span> <span class="n">EXIT_FAILURE</span><span class="p">;</span>
	<span class="p">}</span>
	<span class="n">BIO_free</span><span class="p">(</span><span class="n">b</span><span class="p">);</span>
	<span class="k">return</span> <span class="n">EXIT_SUCCESS</span><span class="p">;</span>
<span class="p">}</span>

<span class="kt">char</span> <span class="n">not_after_str</span><span class="p">[</span><span class="n">DATE_LEN</span><span class="p">];</span>
<span class="n">convert_ASN1TIME</span><span class="p">(</span><span class="n">not_after</span><span class="p">,</span> <span class="n">not_after_str</span><span class="p">,</span> <span class="n">DATE_LEN</span><span class="p">);</span>

<span class="kt">char</span> <span class="n">not_before_str</span><span class="p">[</span><span class="n">DATE_LEN</span><span class="p">];</span>
<span class="n">convert_ASN1TIME</span><span class="p">(</span><span class="n">not_before</span><span class="p">,</span> <span class="n">not_before_str</span><span class="p">,</span> <span class="n">DATE_LEN</span><span class="p">);</span></code></pre></figure>

<h3 id="ca-status">CA Status</h3>

<p>Checking whether a certificate is a valid CA certificate is not a boolean
operation as you might expect. There are several avenues through which a
certificate can be interpreted as CA certificate. As such, instead of directly
checking various X.509 extensions, it is more reliable to use <code class="highlighter-rouge">X509_check_ca</code>.
Any value &gt;= 1 is considered a CA certificate whereas 0 is not a CA certificate.</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">int</span> <span class="n">raw</span> <span class="o">=</span> <span class="n">X509_check_ca</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span></code></pre></figure>

<h3 id="other-x509-extensions">Other X.509 Extensions</h3>

<p>Certificates can contain any other arbitrary extensions. The following code will
loop through all of the extensions on a certificate and print them out:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509_EXTENSION</span><span class="p">)</span> <span class="o">*</span><span class="n">exts</span> <span class="o">=</span> <span class="n">cert</span><span class="o">-&gt;</span><span class="n">cert_info</span><span class="o">-&gt;</span><span class="n">extensions</span><span class="p">;</span>

<span class="kt">int</span> <span class="n">num_of_exts</span><span class="p">;</span>
<span class="k">if</span> <span class="p">(</span><span class="n">exts</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">num_of_exts</span> <span class="o">=</span> <span class="n">sk_X509_EXTENSION_num</span><span class="p">(</span><span class="n">exts</span><span class="p">);</span>
<span class="p">}</span> <span class="k">else</span> <span class="p">{</span>
	<span class="n">num_of_exts</span> <span class="o">=</span> <span class="mi">0</span>
<span class="p">}</span>

<span class="n">IFNEG_FAIL</span><span class="p">(</span><span class="n">num_of_exts</span><span class="p">,</span> <span class="s">"error parsing number of X509v3 extensions."</span><span class="p">);</span>

<span class="k">for</span> <span class="p">(</span><span class="kt">int</span> <span class="n">i</span><span class="o">=</span><span class="mi">0</span><span class="p">;</span> <span class="n">i</span> <span class="o">&lt;</span> <span class="n">num_of_exts</span><span class="p">;</span> <span class="n">i</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>

	<span class="n">X509_EXTENSION</span> <span class="o">*</span><span class="n">ex</span> <span class="o">=</span> <span class="n">sk_X509_EXTENSION_value</span><span class="p">(</span><span class="n">exts</span><span class="p">,</span> <span class="n">i</span><span class="p">);</span>
	<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">ex</span><span class="p">,</span> <span class="s">"unable to extract extension from stack"</span><span class="p">);</span>
	<span class="n">ASN1_OBJECT</span> <span class="o">*</span><span class="n">obj</span> <span class="o">=</span> <span class="n">X509_EXTENSION_get_object</span><span class="p">(</span><span class="n">ex</span><span class="p">);</span>
	<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">obj</span><span class="p">,</span> <span class="s">"unable to extract ASN1 object from extension"</span><span class="p">);</span>

	<span class="n">BIO</span> <span class="o">*</span><span class="n">ext_bio</span> <span class="o">=</span> <span class="n">BIO_new</span><span class="p">(</span><span class="n">BIO_s_mem</span><span class="p">());</span>
	<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">ext_bio</span><span class="p">,</span> <span class="s">"unable to allocate memory for extension value BIO"</span><span class="p">);</span>
	<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">X509V3_EXT_print</span><span class="p">(</span><span class="n">ext_bio</span><span class="p">,</span> <span class="n">ex</span><span class="p">,</span> <span class="mi">0</span><span class="p">,</span> <span class="mi">0</span><span class="p">))</span> <span class="p">{</span>
		<span class="n">M_ASN1_OCTET_STRING_print</span><span class="p">(</span><span class="n">ext_bio</span><span class="p">,</span> <span class="n">ex</span><span class="o">-&gt;</span><span class="n">value</span><span class="p">);</span>
	<span class="p">}</span>

	<span class="n">BUF_MEM</span> <span class="o">*</span><span class="n">bptr</span><span class="p">;</span>
	<span class="n">BIO_get_mem_ptr</span><span class="p">(</span><span class="n">ext_bio</span><span class="p">,</span> <span class="o">&amp;</span><span class="n">bptr</span><span class="p">);</span>
	<span class="n">BIO_set_close</span><span class="p">(</span><span class="n">ext_bio</span><span class="p">,</span> <span class="n">BIO_NOCLOSE</span><span class="p">);</span>

	<span class="c1">// remove newlines
</span>	<span class="kt">int</span> <span class="n">lastchar</span> <span class="o">=</span> <span class="n">bptr</span><span class="o">-&gt;</span><span class="n">length</span><span class="p">;</span>
	<span class="k">if</span> <span class="p">(</span><span class="n">lastchar</span> <span class="o">&gt;</span> <span class="mi">1</span> <span class="o">&amp;&amp;</span> <span class="p">(</span><span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">[</span><span class="n">lastchar</span><span class="o">-</span><span class="mi">1</span><span class="p">]</span> <span class="o">==</span> <span class="sc">'\n'</span> <span class="o">||</span> <span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">[</span><span class="n">lastchar</span><span class="o">-</span><span class="mi">1</span><span class="p">]</span> <span class="o">==</span> <span class="sc">'\r'</span><span class="p">))</span> <span class="p">{</span>
		<span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">[</span><span class="n">lastchar</span><span class="o">-</span><span class="mi">1</span><span class="p">]</span> <span class="o">=</span> <span class="p">(</span><span class="kt">char</span><span class="p">)</span> <span class="mi">0</span><span class="p">;</span>
	<span class="p">}</span>
	<span class="k">if</span> <span class="p">(</span><span class="n">lastchar</span> <span class="o">&gt;</span> <span class="mi">0</span> <span class="o">&amp;&amp;</span> <span class="p">(</span><span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">[</span><span class="n">lastchar</span><span class="p">]</span> <span class="o">==</span> <span class="sc">'\n'</span> <span class="o">||</span> <span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">[</span><span class="n">lastchar</span><span class="p">]</span> <span class="o">==</span> <span class="sc">'\r'</span><span class="p">))</span> <span class="p">{</span>
		<span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">[</span><span class="n">lastchar</span><span class="p">]</span> <span class="o">=</span> <span class="p">(</span><span class="kt">char</span><span class="p">)</span> <span class="mi">0</span><span class="p">;</span>
	<span class="p">}</span>

	<span class="n">BIO_free</span><span class="p">(</span><span class="n">ext_bio</span><span class="p">);</span>

	<span class="kt">unsigned</span> <span class="n">nid</span> <span class="o">=</span> <span class="n">OBJ_obj2nid</span><span class="p">(</span><span class="n">obj</span><span class="p">);</span>
	<span class="k">if</span> <span class="p">(</span><span class="n">nid</span> <span class="o">==</span> <span class="n">NID_undef</span><span class="p">)</span> <span class="p">{</span>
		<span class="c1">// no lookup found for the provided OID so nid came back as undefined.
</span>		<span class="kt">char</span> <span class="n">extname</span><span class="p">[</span><span class="n">EXTNAME_LEN</span><span class="p">];</span>
		<span class="n">OBJ_obj2txt</span><span class="p">(</span><span class="n">extname</span><span class="p">,</span> <span class="n">EXTNAME_LEN</span><span class="p">,</span> <span class="p">(</span><span class="k">const</span> <span class="n">ASN1_OBJECT</span> <span class="o">*</span><span class="p">)</span> <span class="n">obj</span><span class="p">,</span> <span class="mi">1</span><span class="p">);</span>
		<span class="n">printf</span><span class="p">(</span><span class="s">"extension name is %s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">extname</span><span class="p">);</span>
	<span class="p">}</span> <span class="k">else</span> <span class="p">{</span>
		<span class="c1">// the OID translated to a NID which implies that the OID has a known sn/ln
</span>		<span class="k">const</span> <span class="kt">char</span> <span class="o">*</span><span class="n">c_ext_name</span> <span class="o">=</span> <span class="n">OBJ_nid2ln</span><span class="p">(</span><span class="n">nid</span><span class="p">);</span>
		<span class="n">IFNULL_FAIL</span><span class="p">(</span><span class="n">c_ext_name</span><span class="p">,</span> <span class="s">"invalid X509v3 extension name"</span><span class="p">);</span>
		<span class="n">printf</span><span class="p">(</span><span class="s">"extension name is %s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">c_ext_name</span><span class="p">);</span>
	<span class="p">}</span>

	<span class="n">printf</span><span class="p">(</span><span class="s">"extension length is %u</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">bptr</span><span class="o">-&gt;</span><span class="n">length</span><span class="p">)</span>
	<span class="n">printf</span><span class="p">(</span><span class="s">"extension value is %s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">bptr</span><span class="o">-&gt;</span><span class="n">data</span><span class="p">)</span>
<span class="p">}</span></code></pre></figure>

<h2 id="misordered-certificate-chains">Misordered Certificate Chains</h2>

<p>At times, we’ll receive misordered certificate chains. The following code will
attempt to reorder certificates to construct a rational certificate chain based
on each certificate’s subject and issuer string. The algorithm is O(n^2), but we
generally only receive two or three certificates and in the majority-case, they
will already be in the correct order.</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp">	<span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509</span><span class="p">)</span> <span class="o">*</span><span class="n">r_sk</span> <span class="o">=</span> <span class="n">sk_X509_new_null</span><span class="p">();</span>
	<span class="n">sk_X509_push</span><span class="p">(</span><span class="n">r_sk</span><span class="p">,</span> <span class="n">sk_X509_value</span><span class="p">(</span><span class="n">st</span><span class="p">,</span> <span class="mi">0</span><span class="p">));</span>

	<span class="k">for</span> <span class="p">(</span><span class="kt">int</span> <span class="n">i</span><span class="o">=</span><span class="mi">1</span><span class="p">;</span> <span class="n">i</span> <span class="o">&lt;</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">st</span><span class="p">);</span> <span class="n">i</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>
		<span class="n">X509</span> <span class="o">*</span><span class="n">prev</span> <span class="o">=</span> <span class="n">sk_X509_value</span><span class="p">(</span><span class="n">r_sk</span><span class="p">,</span> <span class="n">i</span><span class="o">-</span><span class="mi">1</span><span class="p">);</span>
		<span class="n">X509</span> <span class="o">*</span><span class="n">next</span> <span class="o">=</span> <span class="nb">NULL</span><span class="p">;</span>
		<span class="k">for</span> <span class="p">(</span><span class="kt">int</span> <span class="n">j</span><span class="o">=</span><span class="mi">1</span><span class="p">;</span> <span class="n">j</span> <span class="o">&lt;</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">st</span><span class="p">);</span> <span class="n">j</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>
			<span class="n">X509</span> <span class="o">*</span><span class="n">cand</span> <span class="o">=</span> <span class="n">sk_X509_value</span><span class="p">(</span><span class="n">st</span><span class="p">,</span> <span class="n">j</span><span class="p">);</span>
			<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">X509_NAME_cmp</span><span class="p">(</span><span class="n">cand</span><span class="o">-&gt;</span><span class="n">cert_info</span><span class="o">-&gt;</span><span class="n">subject</span><span class="p">,</span> <span class="n">prev</span><span class="o">-&gt;</span><span class="n">cert_info</span><span class="o">-&gt;</span><span class="n">issuer</span><span class="p">)</span>
					<span class="o">||</span> <span class="n">j</span> <span class="o">==</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">st</span><span class="p">)</span> <span class="o">-</span> <span class="mi">1</span><span class="p">)</span> <span class="p">{</span>
				<span class="n">next</span> <span class="o">=</span> <span class="n">cand</span><span class="p">;</span>
				<span class="k">break</span><span class="p">;</span>
			<span class="p">}</span>
		<span class="p">}</span>
		<span class="k">if</span> <span class="p">(</span><span class="n">next</span><span class="p">)</span> <span class="p">{</span>
			<span class="n">sk_X509_push</span><span class="p">(</span><span class="n">r_sk</span><span class="p">,</span> <span class="n">next</span><span class="p">);</span>
		<span class="p">}</span> <span class="k">else</span> <span class="p">{</span>
			<span class="c1">// we're unable to figure out the correct stack so just use the original one provided.
</span>			<span class="n">sk_X509_free</span><span class="p">(</span><span class="n">r_sk</span><span class="p">);</span>
			<span class="n">r_sk</span> <span class="o">=</span> <span class="n">sk_X509_dup</span><span class="p">(</span><span class="n">st</span><span class="p">);</span>
			<span class="k">break</span><span class="p">;</span>
		<span class="p">}</span>
	<span class="p">}</span></code></pre></figure>

<h2 id="validating-certificates">Validating Certificates</h2>

<p>In our scans, we oftentimes use multiple CA stores in order to emulate different
browsers. Here, we describe how we create specialized stores and validate
against them.</p>

<p>We can create a store based on a particular file with the following:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">X509_STORE</span> <span class="o">*</span><span class="n">s</span> <span class="o">=</span> <span class="n">X509_STORE_new</span><span class="p">();</span>
<span class="k">if</span> <span class="p">(</span><span class="n">s</span> <span class="o">==</span> <span class="nb">NULL</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to create new X509 store.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="nb">NULL</span><span class="p">;</span>
<span class="p">}</span>
<span class="kt">int</span> <span class="n">rc</span> <span class="o">=</span> <span class="n">X509_STORE_load_locations</span><span class="p">(</span><span class="n">s</span><span class="p">,</span> <span class="n">store_path</span><span class="p">,</span> <span class="nb">NULL</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="n">rc</span> <span class="o">!=</span> <span class="mi">1</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to load certificates at %s to store</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">store_path</span><span class="p">);</span>
	<span class="n">X509_STORE_free</span><span class="p">(</span><span class="n">s</span><span class="p">);</span>
	<span class="k">return</span> <span class="nb">NULL</span><span class="p">;</span>
<span class="p">}</span>
<span class="k">return</span> <span class="n">s</span><span class="p">;</span></code></pre></figure>

<p>And then validate certificates against the store with the following:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">X509_STORE_CTX</span> <span class="o">*</span><span class="n">ctx</span> <span class="o">=</span> <span class="n">X509_STORE_CTX_new</span><span class="p">();</span>
<span class="k">if</span> <span class="p">(</span><span class="o">!</span><span class="n">ctx</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to create STORE CTX</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">return</span> <span class="o">-</span><span class="mi">1</span><span class="p">;</span>
<span class="p">}</span>
<span class="k">if</span> <span class="p">(</span><span class="n">X509_STORE_CTX_init</span><span class="p">(</span><span class="n">ctx</span><span class="p">,</span> <span class="n">store</span><span class="p">,</span> <span class="n">cert</span><span class="p">,</span> <span class="n">st</span><span class="p">)</span> <span class="o">!=</span> <span class="mi">1</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">fprintf</span><span class="p">(</span><span class="n">stderr</span><span class="p">,</span> <span class="s">"unable to initialize STORE CTX.</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="n">X509_STORE_CTX_free</span><span class="p">(</span><span class="n">ctx</span><span class="p">);</span>
	<span class="k">return</span> <span class="o">-</span><span class="mi">1</span><span class="p">;</span>
<span class="p">}</span>
<span class="kt">int</span> <span class="n">rc</span> <span class="o">=</span> <span class="n">X509_verify_cert</span><span class="p">(</span><span class="n">ctx</span><span class="p">);</span>
<span class="n">X509_STORE_CTX_free</span><span class="p">(</span><span class="n">ctx</span><span class="p">);</span>
<span class="k">return</span> <span class="n">rc</span><span class="p">;</span></code></pre></figure>

<p>It’s worth noting that self-signed certificates will always fail OpenSSL’s
validation. While this might make sense in most client applications, we are
oftentimes interested in other errors that might be present. We validate
self-signed certificates by adding them into a temporary store and then
validating against it. It’s a bick hackish, but is much easier than
re-implementing OpenSSL’s validation techniques.</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="n">X509_STORE</span> <span class="o">*</span><span class="n">s</span> <span class="o">=</span> <span class="n">X509_STORE_new</span><span class="p">();</span>
<span class="kt">int</span> <span class="n">num</span> <span class="o">=</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">sk</span><span class="p">);</span>
<span class="n">X509</span> <span class="o">*</span><span class="n">top</span> <span class="o">=</span> <span class="n">sk_X509_value</span><span class="p">(</span><span class="n">st</span><span class="p">,</span> <span class="n">num</span><span class="o">-</span><span class="mi">1</span><span class="p">);</span>
<span class="n">X509_STORE_add_cert</span><span class="p">(</span><span class="n">s</span><span class="p">,</span> <span class="n">top</span><span class="p">);</span>
<span class="n">X509_STORE_CTX</span> <span class="o">*</span><span class="n">ctx</span> <span class="o">=</span> <span class="n">X509_STORE_CTX_new</span><span class="p">();</span>
<span class="n">X509_STORE_CTX_init</span><span class="p">(</span><span class="n">ctx</span><span class="p">,</span> <span class="n">s</span><span class="p">,</span> <span class="n">cert</span><span class="p">,</span> <span class="n">st</span><span class="p">);</span>
<span class="kt">int</span> <span class="n">rc</span> <span class="o">=</span> <span class="n">X509_verify_cert</span><span class="p">(</span><span class="n">ctx</span><span class="p">);</span>
<span class="k">if</span> <span class="p">(</span><span class="n">rc</span> <span class="o">==</span> <span class="mi">1</span><span class="p">)</span> <span class="p">{</span>
	<span class="c1">// validated OK. either trusted or self signed.
</span><span class="p">}</span> <span class="k">else</span> <span class="p">{</span>
	<span class="c1">// validation failed
</span>	<span class="kt">int</span> <span class="n">err</span> <span class="o">=</span> <span class="n">X509_STORE_CTX_get_error</span><span class="p">(</span><span class="n">ctx</span><span class="p">);</span>
<span class="p">}</span>

<span class="c1">// any additional processing..
</span>
<span class="n">X509_STORE_CTX_free</span><span class="p">(</span><span class="n">ctx</span><span class="p">);</span>
<span class="n">X509_STORE_free</span><span class="p">(</span><span class="n">s</span><span class="p">);</span></code></pre></figure>

<p>Sometimes you will also find that you just need to check whether a certificate
has been issued by a trusted source instead of just considering whether it is
currently valid, which can be done using <code class="highlighter-rouge">X509_check_issued</code>. For example, if
you wanted to check whether a certificate was self-signed:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="k">if</span> <span class="p">(</span><span class="n">X509_check_issued</span><span class="p">(</span><span class="n">cert</span><span class="p">,</span> <span class="n">cert</span><span class="p">)</span> <span class="o">==</span> <span class="n">X509_V_OK</span><span class="p">)</span> <span class="p">{</span>
	<span class="n">is_self_signed</span> <span class="o">=</span> <span class="mi">1</span><span class="p">;</span>
<span class="p">}</span> <span class="k">else</span> <span class="p">{</span>
	<span class="n">is_self_signed</span> <span class="o">=</span> <span class="mi">0</span><span class="p">;</span>
<span class="p">}</span></code></pre></figure>

<h2 id="helper-functions">Helper Functions</h2>

<p>There are several other functions that were used in troubleshooting and might be
of help while you’re developing code against OpenSSL.</p>

<p>Print out the basic information about a certificate:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="cp">#define MAX_LENGTH 1024
</span>
<span class="kt">void</span> <span class="nf">print_certificate</span><span class="p">(</span><span class="n">X509</span><span class="o">*</span> <span class="n">cert</span><span class="p">)</span> <span class="p">{</span>
	<span class="kt">char</span> <span class="n">subj</span><span class="p">[</span><span class="n">MAX_LENGTH</span><span class="o">+</span><span class="mi">1</span><span class="p">];</span>
	<span class="kt">char</span> <span class="n">issuer</span><span class="p">[</span><span class="n">MAX_LENGTH</span><span class="o">+</span><span class="mi">1</span><span class="p">];</span>
	<span class="n">X509_NAME_oneline</span><span class="p">(</span><span class="n">X509_get_subject_name</span><span class="p">(</span><span class="n">cert</span><span class="p">),</span> <span class="n">subj</span><span class="p">,</span> <span class="n">MAX_LENGTH</span><span class="p">);</span>
	<span class="n">X509_NAME_oneline</span><span class="p">(</span><span class="n">X509_get_issuer_name</span><span class="p">(</span><span class="n">cert</span><span class="p">),</span> <span class="n">issuer</span><span class="p">,</span> <span class="n">MAX_LENGTH</span><span class="p">);</span>
	<span class="n">printf</span><span class="p">(</span><span class="s">"certificate: %s</span><span class="se">\n</span><span class="s">"</span><span class="p">,</span> <span class="n">subj</span><span class="p">);</span>
	<span class="n">printf</span><span class="p">(</span><span class="s">"</span><span class="se">\t</span><span class="s">issuer: %s</span><span class="se">\n\n</span><span class="s">"</span><span class="p">,</span> <span class="n">issuer</span><span class="p">);</span>
<span class="p">}</span></code></pre></figure>

<p>Print out each certificate in a given stack:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">void</span> <span class="nf">print_stack</span><span class="p">(</span><span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509</span><span class="p">)</span><span class="o">*</span> <span class="n">sk</span><span class="p">)</span>
<span class="p">{</span>
	<span class="kt">unsigned</span> <span class="n">len</span> <span class="o">=</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">sk</span><span class="p">);</span>
	<span class="n">printf</span><span class="p">(</span><span class="s">"Begin Certificate Stack:</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
	<span class="k">for</span><span class="p">(</span><span class="kt">unsigned</span> <span class="n">i</span><span class="o">=</span><span class="mi">0</span><span class="p">;</span> <span class="n">i</span><span class="o">&lt;</span><span class="n">len</span><span class="p">;</span> <span class="n">i</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>
		<span class="n">X509</span> <span class="o">*</span><span class="n">cert</span> <span class="o">=</span> <span class="n">sk_X509_value</span><span class="p">(</span><span class="n">sk</span><span class="p">,</span> <span class="n">i</span><span class="p">);</span>
		<span class="n">print_certificate</span><span class="p">(</span><span class="n">cert</span><span class="p">);</span>
	<span class="p">}</span>
	<span class="n">printf</span><span class="p">(</span><span class="s">"End Certificate Stack</span><span class="se">\n</span><span class="s">"</span><span class="p">);</span>
<span class="p">}</span></code></pre></figure>

<p>Check whether two certificate stacks are identical:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">int</span> <span class="nf">certparse_sk_X509_cmp</span><span class="p">(</span><span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509</span><span class="p">)</span> <span class="o">*</span><span class="n">a</span><span class="p">,</span> <span class="n">STACK_OF</span><span class="p">(</span><span class="n">X509</span><span class="p">)</span> <span class="o">*</span><span class="n">b</span><span class="p">)</span>
<span class="p">{</span>
	<span class="kt">int</span> <span class="n">a_len</span> <span class="o">=</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">a</span><span class="p">);</span>
	<span class="kt">int</span> <span class="n">b_len</span> <span class="o">=</span> <span class="n">sk_X509_num</span><span class="p">(</span><span class="n">b</span><span class="p">);</span>
	<span class="k">if</span> <span class="p">(</span><span class="n">a_len</span> <span class="o">!=</span> <span class="n">b_len</span><span class="p">)</span> <span class="p">{</span>
		<span class="k">return</span> <span class="mi">1</span><span class="p">;</span>
	<span class="p">}</span>
	<span class="k">for</span> <span class="p">(</span><span class="kt">int</span> <span class="n">i</span><span class="o">=</span><span class="mi">0</span><span class="p">;</span> <span class="n">i</span> <span class="o">&lt;</span> <span class="n">a_len</span><span class="p">;</span> <span class="n">i</span><span class="o">++</span><span class="p">)</span> <span class="p">{</span>
		<span class="k">if</span> <span class="p">(</span><span class="n">X509_cmp</span><span class="p">(</span><span class="n">sk_X509_value</span><span class="p">(</span><span class="n">a</span><span class="p">,</span> <span class="n">i</span><span class="p">),</span> <span class="n">sk_X509_value</span><span class="p">(</span><span class="n">b</span><span class="p">,</span> <span class="n">i</span><span class="p">)))</span> <span class="p">{</span>
			<span class="k">return</span> <span class="mi">1</span><span class="p">;</span>
		<span class="p">}</span>
	<span class="p">}</span>
	<span class="k">return</span> <span class="mi">0</span><span class="p">;</span>
<span class="p">}</span></code></pre></figure>

<p>Check whether the subject and issuer string on a certificate are identical:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="kt">int</span> <span class="nf">certparse_subjeqissuer</span><span class="p">(</span><span class="n">X509</span> <span class="o">*</span><span class="n">cert</span><span class="p">)</span>
<span class="p">{</span>
	<span class="kt">char</span> <span class="o">*</span><span class="n">s</span> <span class="o">=</span> <span class="n">X509_NAME_oneline</span><span class="p">(</span><span class="n">X509_get_subject_name</span><span class="p">(</span><span class="n">cert</span><span class="p">),</span> <span class="nb">NULL</span><span class="p">,</span> <span class="mi">0</span><span class="p">);</span>
	<span class="kt">char</span> <span class="o">*</span><span class="n">i</span> <span class="o">=</span> <span class="n">X509_NAME_oneline</span><span class="p">(</span><span class="n">X509_get_issuer_name</span><span class="p">(</span><span class="n">cert</span><span class="p">),</span> <span class="nb">NULL</span><span class="p">,</span> <span class="mi">0</span><span class="p">);</span>
	<span class="kt">int</span> <span class="n">rc</span> <span class="o">=</span> <span class="n">strcmp</span><span class="p">(</span><span class="n">s</span><span class="p">,</span> <span class="n">i</span><span class="p">);</span>
	<span class="n">OPENSSL_free</span><span class="p">(</span><span class="n">s</span><span class="p">);</span>
	<span class="n">OPENSSL_free</span><span class="p">(</span><span class="n">i</span><span class="p">);</span>
	<span class="k">return</span> <span class="p">(</span><span class="o">!</span><span class="n">rc</span><span class="p">);</span>
<span class="p">}</span></code></pre></figure>

<p>Convert an OpenSSL error constant into a human readable string:</p>

<figure class="highlight"><pre><code class="language-cpp" data-lang="cpp"><span class="k">const</span> <span class="kt">char</span><span class="o">*</span> <span class="nf">get_validation_errstr</span><span class="p">(</span><span class="kt">long</span> <span class="n">e</span><span class="p">)</span> <span class="p">{</span>
	<span class="k">switch</span> <span class="p">((</span><span class="kt">int</span><span class="p">)</span> <span class="n">e</span><span class="p">)</span> <span class="p">{</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_GET_ISSUER_CERT"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_GET_CRL</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_GET_CRL"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_SIGNATURE_FAILURE</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_SIGNATURE_FAILURE"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CRL_SIGNATURE_FAILURE</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CRL_SIGNATURE_FAILURE"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_NOT_YET_VALID</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_NOT_YET_VALID"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_HAS_EXPIRED</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_HAS_EXPIRED"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CRL_NOT_YET_VALID</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CRL_NOT_YET_VALID"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CRL_HAS_EXPIRED</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CRL_HAS_EXPIRED"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_ERROR_IN_CERT_NOT_AFTER_FIELD"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_OUT_OF_MEM</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_OUT_OF_MEM"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_DEPTH_ZERO_SELF_SIGNED_CERT"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_SELF_SIGNED_CERT_IN_CHAIN"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_CHAIN_TOO_LONG</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_CHAIN_TOO_LONG"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_REVOKED</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_REVOKED"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_INVALID_CA</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_INVALID_CA"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_PATH_LENGTH_EXCEEDED</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_PATH_LENGTH_EXCEEDED"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_INVALID_PURPOSE</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_INVALID_PURPOSE"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_UNTRUSTED</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_UNTRUSTED"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_CERT_REJECTED</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_CERT_REJECTED"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_SUBJECT_ISSUER_MISMATCH</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_SUBJECT_ISSUER_MISMATCH"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_AKID_SKID_MISMATCH</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_AKID_SKID_MISMATCH"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_AKID_ISSUER_SERIAL_MISMATCH"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_KEYUSAGE_NO_CERTSIGN</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_KEYUSAGE_NO_CERTSIGN"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_INVALID_EXTENSION</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_INVALID_EXTENSION"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_INVALID_POLICY_EXTENSION</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_INVALID_POLICY_EXTENSION"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_NO_EXPLICIT_POLICY</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_NO_EXPLICIT_POLICY"</span><span class="p">;</span>
		<span class="k">case</span> <span class="n">X509_V_ERR_APPLICATION_VERIFICATION</span><span class="p">:</span>
			<span class="k">return</span> <span class="s">"ERR_APPLICATION_VERIFICATION"</span><span class="p">;</span>
		<span class="nl">default:</span>
			<span class="k">return</span> <span class="s">"ERR_UNKNOWN"</span><span class="p">;</span>
	<span class="p">}</span>
<span class="p">}</span></code></pre></figure>

<p>I hope this helps. As I stated earlier, if you find other pieces of information
useful, let me know and we’ll get things updated. Similarly, if you find that
any of the examples don’t work, let me know.</p>

<p>Thanks to Jordan Whitehead for various corrections.</p>

</div>


        </div>
      </div>
    </div>
    <script>
      (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
      (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
      m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
      })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

      ga('create', 'UA-32099137-1', 'auto');
      ga('send', 'pageview');
    </script>
  </body>
</html>

