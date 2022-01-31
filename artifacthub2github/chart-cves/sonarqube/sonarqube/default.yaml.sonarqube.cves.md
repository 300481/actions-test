<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <style>
      * {
        font-family: Arial, Helvetica, sans-serif;
      }
      h1 {
        text-align: center;
      }
      .group-header th {
        font-size: 200%;
      }
      .sub-header th {
        font-size: 150%;
      }
      table, th, td {
        border: 1px solid black;
        border-collapse: collapse;
        white-space: nowrap;
        padding: .3em;
      }
      table {
        margin: 0 auto;
      }
      .severity {
        text-align: center;
        font-weight: bold;
        color: #fafafa;
      }
      .severity-LOW .severity { background-color: #5fbb31; }
      .severity-MEDIUM .severity { background-color: #e9c600; }
      .severity-HIGH .severity { background-color: #ff8800; }
      .severity-CRITICAL .severity { background-color: #e40000; }
      .severity-UNKNOWN .severity { background-color: #747474; }
      .severity-LOW { background-color: #5fbb3160; }
      .severity-MEDIUM { background-color: #e9c60060; }
      .severity-HIGH { background-color: #ff880060; }
      .severity-CRITICAL { background-color: #e4000060; }
      .severity-UNKNOWN { background-color: #74747460; }
      table tr td:first-of-type {
        font-weight: bold;
      }
      .links a,
      .links[data-more-links=on] a {
        display: block;
      }
      .links[data-more-links=off] a:nth-of-type(1n+5) {
        display: none;
      }
      a.toggle-more-links { cursor: pointer; }
    </style>
    <title>sonarqube:9.3.0-community (alpine 3.14.3) - Trivy Report - 2022-01-31T14:32:02.334223807Z</title>
    <script>
      window.onload = function() {
        document.querySelectorAll('td.links').forEach(function(linkCell) {
          var links = [].concat.apply([], linkCell.querySelectorAll('a'));
          [].sort.apply(links, function(a, b) {
            return a.href > b.href ? 1 : -1;
          });
          links.forEach(function(link, idx) {
            if (links.length > 3 && 3 === idx) {
              var toggleLink = document.createElement('a');
              toggleLink.innerText = "Toggle more links";
              toggleLink.href = "#toggleMore";
              toggleLink.setAttribute("class", "toggle-more-links");
              linkCell.appendChild(toggleLink);
            }
            linkCell.appendChild(link);
          });
        });
        document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
          toggleLink.onclick = function() {
            var expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
            return false;
          };
        });
      };
    </script>
  </head>
  <body>
    <h1>sonarqube:9.3.0-community (alpine 3.14.3) - Trivy Report - 2022-01-31T14:32:02.334240207Z</h1>
    <table>
      <tr class="group-header"><th colspan="6">alpine</th></tr>
      <tr><th colspan="6">No Vulnerabilities found</th></tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
      <tr class="group-header"><th colspan="6">jar</th></tr>
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
        <th>Links</th>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">com.google.protobuf:protobuf-java</td>
        <td>CVE-2021-22569</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">3.15.8</td>
        <td>3.19.2, 3.18.2, 3.16.1</td>
        <td class="links" data-more-links="off">
          <a href="http://www.openwall.com/lists/oss-security/2022/01/12/4">http://www.openwall.com/lists/oss-security/2022/01/12/4</a>
          <a href="http://www.openwall.com/lists/oss-security/2022/01/12/7">http://www.openwall.com/lists/oss-security/2022/01/12/7</a>
          <a href="https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=39330">https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=39330</a>
          <a href="https://cloud.google.com/support/bulletins#gcp-2022-001">https://cloud.google.com/support/bulletins#gcp-2022-001</a>
          <a href="https://github.com/advisories/GHSA-wrvw-hg22-4m67">https://github.com/advisories/GHSA-wrvw-hg22-4m67</a>
          <a href="https://github.com/protocolbuffers/protobuf/commit/b3093dce58bc9d3042f085666d83c8ef1f51fe7b">https://github.com/protocolbuffers/protobuf/commit/b3093dce58bc9d3042f085666d83c8ef1f51fe7b</a>
          <a href="https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-wrvw-hg22-4m67">https://github.com/protocolbuffers/protobuf/security/advisories/GHSA-wrvw-hg22-4m67</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-22569">https://nvd.nist.gov/vuln/detail/CVE-2021-22569</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">com.h2database:h2</td>
        <td>CVE-2021-42392</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.4.199</td>
        <td>2.0.206</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-h376-j262-vhq6">https://github.com/advisories/GHSA-h376-j262-vhq6</a>
          <a href="https://github.com/h2database/h2database/releases/tag/version-2.0.206">https://github.com/h2database/h2database/releases/tag/version-2.0.206</a>
          <a href="https://github.com/h2database/h2database/security/advisories/GHSA-h376-j262-vhq6">https://github.com/h2database/h2database/security/advisories/GHSA-h376-j262-vhq6</a>
          <a href="https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console/">https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console/</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-42392">https://nvd.nist.gov/vuln/detail/CVE-2021-42392</a>
          <a href="https://security.netapp.com/advisory/ntap-20220119-0001/">https://security.netapp.com/advisory/ntap-20220119-0001/</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">com.h2database:h2</td>
        <td>CVE-2022-23221</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">1.4.199</td>
        <td>2.1.210</td>
        <td class="links" data-more-links="off">
          <a href="http://packetstormsecurity.com/files/165676/H2-Database-Console-Remote-Code-Execution.html">http://packetstormsecurity.com/files/165676/H2-Database-Console-Remote-Code-Execution.html</a>
          <a href="http://seclists.org/fulldisclosure/2022/Jan/39">http://seclists.org/fulldisclosure/2022/Jan/39</a>
          <a href="https://github.com/advisories/GHSA-45hx-wfhj-473x">https://github.com/advisories/GHSA-45hx-wfhj-473x</a>
          <a href="https://github.com/h2database/h2database/releases/tag/version-2.1.210">https://github.com/h2database/h2database/releases/tag/version-2.1.210</a>
          <a href="https://github.com/h2database/h2database/security/advisories">https://github.com/h2database/h2database/security/advisories</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2022-23221">https://nvd.nist.gov/vuln/detail/CVE-2022-23221</a>
          <a href="https://twitter.com/d0nkey_man/status/1483824727936450564">https://twitter.com/d0nkey_man/status/1483824727936450564</a>
        </td>
      </tr>
      <tr class="severity-HIGH">
        <td class="pkg-name">com.h2database:h2</td>
        <td>CVE-2021-23463</td>
        <td class="severity">HIGH</td>
        <td class="pkg-version">1.4.199</td>
        <td>2.0.202</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-7rpj-hg47-cx62">https://github.com/advisories/GHSA-7rpj-hg47-cx62</a>
          <a href="https://github.com/h2database/h2database/commit/d83285fd2e48fb075780ee95badee6f5a15ea7f8%23diff-008c2e4462609982199cd83e7cf6f1d6b41296b516783f6752c44b9f15dc7bc3">https://github.com/h2database/h2database/commit/d83285fd2e48fb075780ee95badee6f5a15ea7f8%23diff-008c2e4462609982199cd83e7cf6f1d6b41296b516783f6752c44b9f15dc7bc3</a>
          <a href="https://github.com/h2database/h2database/issues/3195">https://github.com/h2database/h2database/issues/3195</a>
          <a href="https://github.com/h2database/h2database/pull/3199">https://github.com/h2database/h2database/pull/3199</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-23463">https://nvd.nist.gov/vuln/detail/CVE-2021-23463</a>
          <a href="https://snyk.io/vuln/SNYK-JAVA-COMH2DATABASE-1769238">https://snyk.io/vuln/SNYK-JAVA-COMH2DATABASE-1769238</a>
        </td>
      </tr>
      <tr class="severity-CRITICAL">
        <td class="pkg-name">com.hazelcast:hazelcast</td>
        <td>GHSA-v57x-gxfj-484q</td>
        <td class="severity">CRITICAL</td>
        <td class="pkg-version">4.2.2</td>
        <td>4.2.4, 4.1.8, 4.0.5, 5.0.2</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-v57x-gxfj-484q">https://github.com/advisories/GHSA-v57x-gxfj-484q</a>
          <a href="https://github.com/hazelcast/hazelcast/security/advisories/GHSA-v57x-gxfj-484q">https://github.com/hazelcast/hazelcast/security/advisories/GHSA-v57x-gxfj-484q</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">io.netty:netty-codec</td>
        <td>CVE-2021-37136</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.1.66.Final</td>
        <td>4.1.68.Final</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-grg4-wf29-r9vv">https://github.com/advisories/GHSA-grg4-wf29-r9vv</a>
          <a href="https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java#L294">https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java#L294</a>
          <a href="https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java#L305">https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java#L305</a>
          <a href="https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java#L80">https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/Bzip2Decoder.java#L80</a>
          <a href="https://github.com/netty/netty/commit/41d3d61a61608f2223bb364955ab2045dd5e4020">https://github.com/netty/netty/commit/41d3d61a61608f2223bb364955ab2045dd5e4020</a>
          <a href="https://github.com/netty/netty/security/advisories/GHSA-grg4-wf29-r9vv">https://github.com/netty/netty/security/advisories/GHSA-grg4-wf29-r9vv</a>
          <a href="https://lists.apache.org/thread.html/r06a145c9bd41a7344da242cef07977b24abe3349161ede948e30913d@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r06a145c9bd41a7344da242cef07977b24abe3349161ede948e30913d@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5406eaf3b07577d233b9f07cfc8f26e28369e6bab5edfcab41f28abb@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r5406eaf3b07577d233b9f07cfc8f26e28369e6bab5edfcab41f28abb@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5e05eba32476c580412f9fbdfc9b8782d5b40558018ac4ac07192a04@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r5e05eba32476c580412f9fbdfc9b8782d5b40558018ac4ac07192a04@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r75490c61c2cb7b6ae2c81238fd52ae13636c60435abcd732d41531a0@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r75490c61c2cb7b6ae2c81238fd52ae13636c60435abcd732d41531a0@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd262f59b1586a108e320e5c966feeafbb1b8cdc96965debc7cc10b16@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/rd262f59b1586a108e320e5c966feeafbb1b8cdc96965debc7cc10b16@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rfb2bf8597e53364ccab212fbcbb2a4e9f0a9e1429b1dc08023c6868e@%3Cdev.tinkerpop.apache.org%3E">https://lists.apache.org/thread.html/rfb2bf8597e53364ccab212fbcbb2a4e9f0a9e1429b1dc08023c6868e@%3Cdev.tinkerpop.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37136">https://nvd.nist.gov/vuln/detail/CVE-2021-37136</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">io.netty:netty-codec</td>
        <td>CVE-2021-37137</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.1.66.Final</td>
        <td>4.1.68.Final</td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/advisories/GHSA-9vjp-v76f-g363">https://github.com/advisories/GHSA-9vjp-v76f-g363</a>
          <a href="https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java#L171">https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java#L171</a>
          <a href="https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java#L185">https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java#L185</a>
          <a href="https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java#L79">https://github.com/netty/netty/blob/4.1/codec/src/main/java/io/netty/handler/codec/compression/SnappyFrameDecoder.java#L79</a>
          <a href="https://github.com/netty/netty/commit/6da4956b31023ae967451e1d94ff51a746a9194f">https://github.com/netty/netty/commit/6da4956b31023ae967451e1d94ff51a746a9194f</a>
          <a href="https://github.com/netty/netty/security/advisories/GHSA-9vjp-v76f-g363">https://github.com/netty/netty/security/advisories/GHSA-9vjp-v76f-g363</a>
          <a href="https://github.com/netty/netty/security/advisories/GHSA-grg4-wf29-r9vv">https://github.com/netty/netty/security/advisories/GHSA-grg4-wf29-r9vv</a>
          <a href="https://lists.apache.org/thread.html/r06a145c9bd41a7344da242cef07977b24abe3349161ede948e30913d@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r06a145c9bd41a7344da242cef07977b24abe3349161ede948e30913d@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5406eaf3b07577d233b9f07cfc8f26e28369e6bab5edfcab41f28abb@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r5406eaf3b07577d233b9f07cfc8f26e28369e6bab5edfcab41f28abb@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r5e05eba32476c580412f9fbdfc9b8782d5b40558018ac4ac07192a04@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r5e05eba32476c580412f9fbdfc9b8782d5b40558018ac4ac07192a04@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/r75490c61c2cb7b6ae2c81238fd52ae13636c60435abcd732d41531a0@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/r75490c61c2cb7b6ae2c81238fd52ae13636c60435abcd732d41531a0@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rd262f59b1586a108e320e5c966feeafbb1b8cdc96965debc7cc10b16@%3Ccommits.druid.apache.org%3E">https://lists.apache.org/thread.html/rd262f59b1586a108e320e5c966feeafbb1b8cdc96965debc7cc10b16@%3Ccommits.druid.apache.org%3E</a>
          <a href="https://lists.apache.org/thread.html/rfb2bf8597e53364ccab212fbcbb2a4e9f0a9e1429b1dc08023c6868e@%3Cdev.tinkerpop.apache.org%3E">https://lists.apache.org/thread.html/rfb2bf8597e53364ccab212fbcbb2a4e9f0a9e1429b1dc08023c6868e@%3Cdev.tinkerpop.apache.org%3E</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-37137">https://nvd.nist.gov/vuln/detail/CVE-2021-37137</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">io.netty:netty-codec-http</td>
        <td>CVE-2021-43797</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">4.1.66.Final</td>
        <td>4.1.71.Final</td>
        <td class="links" data-more-links="off">
          <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43797">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-43797</a>
          <a href="https://github.com/advisories/GHSA-wx5j-54mm-rqqq">https://github.com/advisories/GHSA-wx5j-54mm-rqqq</a>
          <a href="https://github.com/netty/netty/commit/07aa6b5938a8b6ed7a6586e066400e2643897323">https://github.com/netty/netty/commit/07aa6b5938a8b6ed7a6586e066400e2643897323</a>
          <a href="https://github.com/netty/netty/commit/07aa6b5938a8b6ed7a6586e066400e2643897323 (netty-4.1.71.Final)">https://github.com/netty/netty/commit/07aa6b5938a8b6ed7a6586e066400e2643897323 (netty-4.1.71.Final)</a>
          <a href="https://github.com/netty/netty/pull/11891">https://github.com/netty/netty/pull/11891</a>
          <a href="https://github.com/netty/netty/security/advisories/GHSA-wx5j-54mm-rqqq">https://github.com/netty/netty/security/advisories/GHSA-wx5j-54mm-rqqq</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2021-43797">https://nvd.nist.gov/vuln/detail/CVE-2021-43797</a>
          <a href="https://security.netapp.com/advisory/ntap-20220107-0003/">https://security.netapp.com/advisory/ntap-20220107-0003/</a>
        </td>
      </tr>
      <tr class="severity-MEDIUM">
        <td class="pkg-name">org.nanohttpd:nanohttpd</td>
        <td>CVE-2020-13697</td>
        <td class="severity">MEDIUM</td>
        <td class="pkg-version">2.3.1</td>
        <td></td>
        <td class="links" data-more-links="off">
          <a href="https://github.com/NanoHttpd/nanohttpd">https://github.com/NanoHttpd/nanohttpd</a>
          <a href="https://github.com/advisories/GHSA-pr5m-4w22-8483">https://github.com/advisories/GHSA-pr5m-4w22-8483</a>
          <a href="https://nvd.nist.gov/vuln/detail/CVE-2020-13697">https://nvd.nist.gov/vuln/detail/CVE-2020-13697</a>
          <a href="https://www.vdoo.com/advisories">https://www.vdoo.com/advisories</a>
          <a href="https://www.vdoo.com/advisories/#CVE-2020-13697">https://www.vdoo.com/advisories/#CVE-2020-13697</a>
        </td>
      </tr>
      <tr><th colspan="6">No Misconfigurations found</th></tr>
    </table>
  </body>
</html>
