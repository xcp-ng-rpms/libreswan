%global _hardened_build 1
# These are rpm macros and are 0 or 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# minimum version for support for rhbz#1651314
# should prob update for nss with IKEv1 quick mode support
%global nss_version 3.53.1
%global unbound_version 1.6.6
%global libreswan_config \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    FINALNSSDIR=%{_sysconfdir}/ipsec.d \\\
    INITSYSTEM=systemd \\\
    NSS_HAS_IPSEC_PROFILE=true \\\
    NSS_REQ_AVA_COPY=false \\\
    PREFIX=%{_prefix} \\\
    PYTHON_BINARY=%{__python3} \\\
    SHELL_BINARY=%{_bindir}/sh \\\
    USE_DNSSEC=true \\\
    USE_FIPSCHECK=false \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_LINUX_AUDIT=true \\\
    USE_NM=true \\\
    USE_NSS_KDF=true \\\
    USE_SECCOMP=true \\\
    USE_AUTHPAM=true \\\
    USE_DH2=true \\\
%{nil}

#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: 4.12
Release: 2.3.1%{?dist}
License: GPLv2
Url: https://libreswan.org/

Source0: https://download.libreswan.org/%{?prever:with_development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif

Patch1: libreswan-4.3-maintain-different-v1v2-split.patch
Patch2: libreswan-3.32-1861360-nodefault-rsa-pss.patch
Patch3: libreswan-4.1-maintain-obsolete-keywords.patch
Patch6: libreswan-4.3-1934186-config.patch
Patch7: libreswan-4.9-2176248-authby-rsasig.patch
Patch8: libreswan-4.12-ikev2-auth-delete-state.patch

# XCP-ng patches
Patch1000: cve-2024-3652.patch

BuildRequires: audit-libs-devel
BuildRequires: bison
BuildRequires: curl-devel
BuildRequires: flex
BuildRequires: devtoolset-11-gcc make
BuildRequires: ldns-devel
BuildRequires: libcap-ng-devel
BuildRequires: libevent-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: nspr-devel
BuildRequires: nss-devel >= %{nss_version}
BuildRequires: nss-tools
BuildRequires: openldap-devel
BuildRequires: pam-devel
BuildRequires: pkgconfig
BuildRequires: hostname
BuildRequires: redhat-rpm-config
BuildRequires: systemd-devel
BuildRequires: unbound-devel >= %{unbound_version}
BuildRequires: xmlto
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
Requires: iproute >= 2.6.8
Requires: nss >= %{nss_version}
Requires: nss-softokn
Requires: nss-tools
Requires: unbound-libs >= %{unbound_version}
Requires(post): bash
Requires(post): coreutils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Libreswan is a free implementation of IKE/IPsec for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan.

Libreswan also supports IKEv2 (RFC7296) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%prep
%setup -q -n libreswan-%{version}%{?prever}
%patch1 -p1
%patch2 -p1
%patch3 -p1
%patch6 -p1
%patch7 -p1
%patch8 -p1
%patch1000 -p1

# linking to freebl is not needed
sed -i "s/-lfreebl //" mk/config.mk

# enable crypto-policies support
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" configs/ipsec.conf.in

%build
source /opt/rh/devtoolset-11/enable
make %{?_smp_mflags} \
%if 0%{with_development}
    OPTIMIZE_CFLAGS="%{?_hardened_cflags}" \
%else
    OPTIMIZE_CFLAGS="%{optflags}" \
%endif
%if 0%{with_efence}
    USE_EFENCE=true \
%endif
    WERROR_CFLAGS="-Werror -Wno-missing-field-initializers" \
    USERLINK="%{?__global_ldflags}" \
    %{libreswan_config} \
    programs
FS=$(pwd)

%install
source /opt/rh/devtoolset-11/enable
make \
  DESTDIR=%{buildroot} \
  %{libreswan_config} \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan
rm -rf %{buildroot}%{_libexecdir}/ipsec/*check

install -d -m 0755 %{buildroot}%{_rundir}/pluto
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysconfdir}/sysctl.d
install -m 0644 packaging/fedora/libreswan-sysctl.conf \
  %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

echo "include %{_sysconfdir}/ipsec.d/*.secrets" \
     > %{buildroot}%{_sysconfdir}/ipsec.secrets
rm -fr %{buildroot}%{_sysconfdir}/rc.d/rc*

%if 0%{with_cavstests}
%check
# There is an elaborate upstream testing infrastructure which we do not
# run here - it takes hours and uses kvm
# We only run the CAVS tests.
cp %{SOURCE1} %{SOURCE2} %{SOURCE3} .
bunzip2 *.fax.bz2

: starting CAVS test for IKEv2
%{buildroot}%{_libexecdir}/ipsec/cavp -v2 ikev2.fax | \
    diff -u ikev2.fax - > /dev/null
: starting CAVS test for IKEv1 RSASIG
%{buildroot}%{_libexecdir}/ipsec/cavp -v1dsa ikev1_dsa.fax | \
    diff -u ikev1_dsa.fax - > /dev/null
: starting CAVS test for IKEv1 PSK
%{buildroot}%{_libexecdir}/ipsec/cavp -v1psk ikev1_psk.fax | \
    diff -u ikev1_psk.fax - > /dev/null
: CAVS tests passed

# Some of these tests will show ERROR for negative testing - it will exit on real errors
%{buildroot}%{_libexecdir}/ipsec/algparse -tp || { echo prooposal test failed; exit 1; }
%{buildroot}%{_libexecdir}/ipsec/algparse -ta || { echo algorithm test failed; exit 1; }
: Algorithm parser tests passed

# self test for pluto daemon - this also shows which algorithms it allows in FIPS mode
tmpdir=$(mktemp -d /tmp/libreswan-XXXXX)
certutil -N -d sql:$tmpdir --empty-password
%{buildroot}%{_libexecdir}/ipsec/pluto --selftest --nssdir $tmpdir --rundir $tmpdir
: pluto self-test passed - verify FIPS algorithms allowed is still compliant with NIST

%endif

%post
%systemd_post ipsec.service

%preun
%systemd_preun ipsec.service

%postun
%systemd_postun_with_restart ipsec.service

%files
%doc CHANGES COPYING CREDITS README* LICENSE
%doc docs/*.* docs/examples
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.conf
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ipsec.secrets
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d
%attr(0700,root,root) %dir %{_sysconfdir}/ipsec.d/policies
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ipsec.d/policies/*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sysctl.d/50-libreswan.conf
%attr(0755,root,root) %dir %{_rundir}/pluto
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%config(noreplace) %{_sysconfdir}/logrotate.d/libreswan
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%attr(0644,root,root) %doc %{_mandir}/*/*

%changelog
* Fri Aug 16 2024 David Morel <david.morel@vates.tech> - 4.12-2.3.1
- Sync with CentOS 8 Stream version 4.12-2.el8.3
- Build with GCC 11
- Include fix for CVE-2024-3652 from Alma 8

* Wed Apr 17 2024 Daiki Ueno <dueno@redhat.com> - 4.12-2.3
- Bump release to ensure el8 package is greater than el8_* packages

* Tue Apr 16 2024 Daiki Ueno <dueno@redhat.com> - 4.12-2.2
- Fix patch application in the previous change

* Mon Apr 15 2024 Daiki Ueno <dueno@redhat.com> - 4.12-2.1
- Fix CVE-2024-2357 (RHEL-28742)

* Fri Aug 25 2023 Daiki Ueno <dueno@redhat.com> - 4.12-2
- Resolves: rhbz#2234731 authby=rsasig fails in FIPS policy

* Wed Aug  9 2023 Daiki Ueno <dueno@redhat.com> - 4.12-1
- Update to 4.12 to fix CVE-2023-38710, CVE-2023-38711, CVE-2023-38712
- Resolves: rhbz#2215955

* Thu May 04 2023 Sahana Prasad <sahana@redhat.com> - 4.9-2
- Fix CVE-2023-30570 Malicious IKEv1 Aggressive Mode packets can crash libreswan
- Resolves: rhbz#2187179

* Mon Jan  9 2023 Daiki Ueno <dueno@redhat.com> - 4.9-1
- Resolves: rhbz#2128672 Rebase libreswan to 4.9
- Remove libreswan-4.4-ikev1-disable-diagnostics.patch no longer necessary

* Thu Jan 13 2022 Daiki Ueno <dueno@redhat.com> - 4.5-1
- Resolves: rhbz#2017352 Rebase libreswan to 4.5
- Resolves: rhbz#2036903 ikev1: disable diagnostics logging on receiving malformed packets

* Wed May 26 2021 Daiki Ueno <dueno@redhat.com> - 4.4-1
- Resolves: rhbz#1958968 Rebase libreswan to 4.4
- Resolves: rhbz#1954423 Libreswan: TS_UNACCEPTABLE on multiple connections between the same peers

* Thu Mar 04 2021 Paul Wouters <pwouters@redhat.com> - 4.3-3
- Resolves: rhbz#1933064 - IKEv2 support for Labeled IPsec
- Resolves: rhbz#1935150 RFE: Support IKE and ESP over TCP: RFC 8229
- Resolves: rhbz#1935339 virtual_private setting is missing in the default config

* Sun Feb 21 2021 Paul Wouters <pwouters@redhat.com> - 4.3-1
- Resolves: rhbz#1025061 - IKEv2 support for Labeled IPsec [update]

* Thu Feb 04 2021 Paul Wouters <pwouters@redhat.com> - 4.2-1
- Resolves: rhbz#1891128 [Rebase] rebase libreswan to 4.2
- Resolves: rhbz#1025061 - IKEv2 support for Labeled IPsec

* Tue Oct 27 2020 Paul Wouters <pwouters@redhat.com> - 4.1-1
- Resolves: rhbz#1891128 [Rebase] rebase libreswan to 4.1
- Resolves: rhbz#1889836 libreswan: add 3.x compat patches for obsoleted/removed keywords of 4.0 and re-port ikev2= patch

* Wed Jul 29 2020 Paul Wouters <pwouters@redhat.com> - 3.32-6
- Resolves: rhbz#1861360 authby=rsasig must not imply usage of rsa-pss

* Wed Jul 22 2020 Paul Wouters <pwouters@redhat.com> - 3.32-5
- Resolves: rhbz#1820206 Rebase to libreswan 3.32 [rebuild for USE_NSS_PRF]

* Wed Jul 01 2020 Paul Wouters <pwouters@redhat.com> - 3.32-4
- Resolves: rhbz#1544463 ipsec service does not work correctly when seccomp filtering is enabled

* Wed Jun 17 2020 Paul Wouters <pwouters@redhat.com> - 3.32-3
- Resolves: rhbz#1842597 regression: libreswan does not send PLUTO_BYTES env variables to updown script
- Resolves: rhbz#1847766 subsequent xfrmi interfaces configured outside of libreswan are not recognised properly
- Resolves: rhbz#1840212 protect libreswan against unannounced nss ABI change

* Thu Jun 11 2020 Paul Wouters <pwouters@redhat.com> - 3.32-2
- Resolves: rhbz#1820206 Rebase to libreswan 3.32 [addconn fix]

* Thu Apr 30 2020 Paul Wouters <pwouters@redhat.com> - 3.32-1
- Resolves: rhbz#1820206 Rebase to libreswan 3.32
- Resolves: rhbz#1816265 Use NSS to check whether FIPS mode is enabled
- Resolves: rhbz#1826337 libreswan in FIPS mode rejects ECDSA keys based on faulty RSA key size check being applied

* Tue Aug 13 2019 Paul Wouters <pwouters@redhat.com> - 3.29-6
- Resolves: rhbz#1714331 support NSS based IKE KDF's [require updated nss for rhbz 1738689, memleak fix]

* Thu Aug 08 2019 Paul Wouters <pwouters@redhat.com> - 3.29-5
- Resolves: rhbz#1714331 support NSS based IKE KDF's so libreswan does not need FIPS certification

* Thu Aug 01 2019 Paul Wouters <pwouters@redhat.com> - 3.29-4
- Resolves: rhbz#1699318 'ipsec show' has python3 invalid syntax

* Thu Jul 04 2019 Paul Wouters <pwouters@redhat.com> - 3.29-3
- Resolves: rhbz#1725205 XFRM policy for OE/32 peer is deleted when shunts for previous half-open state expire

* Thu Jun 27 2019 Paul Wouters <pwouters@redhat.com> - 3.29-2
- Resolves: rhbz#1723957 libreswan is missing linux audit calls for failed IKE SAs and failed IPsec SAs required for Common Criteria

* Mon Jun 10 2019 Paul Wouters <pwouters@redhat.com> - 3.29-1
- Resolves: rhbz#1712555 libreswan rebase to 3.29

* Tue May 28 2019 Paul Wouters <pwouters@redhat.com> - 3.28-2
- Resolves: rhbz#1713734: barf: shell syntax error in barf diagnostic tool

* Tue May 21 2019 Paul Wouters <pwouters@redhat.com> - 3.28-1
- Resolves: rhbz#1712555 libreswan rebase to 3.28
- Resolves: rhbz#1683706 Libreswan shows incorrect error messages
- Resolves: rhbz#1706180 Remove last usage of old (unused) PF_KEY API
- Resolves: rhbz#1677045 Opportunistic IPsec instances of /32 groups or auto=start that receive delete won't restart
- Resolves: rhbz#1686990 IKEv1 traffic interruption when responder deletes SAs 60 seconds before EVENT_SA_REPLACE
- Resolves: rhbz#1608353 /usr/sbin/ipsec part of the libreswan packages still invokes commands that were deprecated a decade ago
- Resolves: rhbz#1699318 'ipsec show' has python3 invalid syntax
- Resolves: rhbz#1679394 libreswan using NSS IPsec profiles regresses when critical flags are set causing validation failure

* Thu Feb 21 2019 Paul Wouters <pwouters@redhat.com> - 3.27-9
- Resolves: rhbz#1648776 limit connections to be ikev1only or ikev2only and make ikev2only the default [man page update]

* Fri Feb 15 2019 Paul Wouters <pwouters@redhat.com> - 3.27-8
- Resolves: rhbz#1664101 system wide crypto policies causing IKE_INIT packet fragmentation

* Tue Feb 05 2019 Paul Wouters <pwouters@redhat.com> - 3.27-7
- Resolves: rhbz#1671793 proessing ISAKMP_NEXT_D with additional payloads causes dangling pointer to deleted state

* Fri Feb 01 2019 Paul Wouters <pwouters@redhat.com> - 3.27-6
- Resolves: rhbz#1668342 SELinux prevents libreswan from using some outbound ports causing DNS resolution failures at connection at load time

* Thu Jan 10 2019 Paul Wouters <pwouters@redhat.com> - 3.27-5
- Resolves: rhbz#1664522 libreswan 3.25 in FIPS mode is incorrectly rejecting X.509 public keys that are >= 3072 bits

* Mon Dec 10 2018 Paul Wouters <pwouters@redhat.com> - 3.27-4
- Resolves: rhbz#1657846 libreswan no longer needs to provide openswan in rhel8
- Resolves: rhbz#1643388 libreswan: Unable to verify certificate with non-empty Extended Key Usage which does not include serverAuth or clientAuth
- Resolves: rhbz#1657854 remove userland support for deprecated KLIPS IPsec stack support

* Sun Dec 09 2018 Paul Wouters <pwouters@redhat.com> - 3.27-3
- Resolves: rhbz#1648776 limit connections to be ikev1only or ikev2only and make ikev2only the default

* Thu Nov 08 2018 Paul Wouters <pwouters@redhat.com> - 3.27-2
- Resolves: rhbz#1645137 Libreswan segfaults when it loads configuration file with more then 5 connections

* Mon Oct 08 2018 Paul Wouters <pwouters@redhat.com> - 3.27-1
- Resolves: rhbz#1566574 Rebase to libreswan 3.27

* Mon Sep 17 2018 Paul Wouters <pwouters@redhat.com> - 3.26-1
- Resolves: rhbz#1566574 Rebase to libreswan 3.26
- Resolves: rhbz#1527037 libreswan IPSEC implementation: should follow the policies of system-wide crypto policy
- Resolves: rhbz#1375779 [IKEv2 Conformance] Test IKEv2.EN.R.1.1.6.7: Sending INVALID_KE_PAYLOAD failed
- Resolves: rhbz#1085758 [TAHI][IKEv2] IKEv2.EN.I.1.2.1.1: Can't observe CREATE_CHILD_SA request for rekey
- Resolves: rhbz#1053048 [TAHI][IKEv2] IKEv2.EN.I.1.2.4.1-7: libreswan doesn't sent CREATE_CHILD_SA after IKE_SA Lifetime timeout

* Mon Aug 13 2018 Paul Wouters <pwouters@redhat.com> - 3.25-4
- Resolves: rhbz#1590823 libreswan: Use Python 3 in RHEL 8

* Wed Aug 01 2018 Charalampos Stratakis <cstratak@redhat.com> - 3.25-3.1
- Rebuild for platform-python

* Mon Jul 09 2018 Paul Wouters <pwouters@redhat.com> - 3.25-3
- Cleanup shebangs for python3
- Use the same options via macro for make programs and make install
- Remove old ifdefs
- Sync up patches to new upstream version
- Add Requires: for unbound-libs >= 1.6.6
- Enable crypto-policies support
- Make rundir world readable for easier permission granting for socket

* Tue Jun 26 2018 Charalampos Stratakis <cstratak@redhat.com> - 3.23-2.2
- Make python shebangs point to python3

* Fri Jun 22 2018 Troy Dawson <tdawson@redhat.com> - 3.23-2.1
- Fix python shebangs (#1580773)

* Mon Feb 19 2018 Paul Wouters <pwouters@redhat.com> - 3.23-2
- Support crypto-policies package
- Pull in some patches from upstream and IANA registry updates
- gcc7 format-truncate fixes and workarounds

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 3.23-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Thu Jan 25 2018 Paul Wouters <pwouters@redhat.com> - 3.23-1
- Updated to 3.23 - support for MOBIKE, PPK, CMAC, nic offload and performance improvements

* Sat Jan 20 2018 Björn Esser <besser82@fedoraproject.org> - 3.22-1.1
- Rebuilt for switch to libxcrypt

* Mon Oct 23 2017 Paul Wouters <pwouters@redhat.com> - 3.22-1
- Updated to 3.22 - many bugfixes, and unbound ipsecmod support

* Wed Aug  9 2017 Paul Wouters <pwouters@redhat.com> - 3.21-1
- Updated to 3.21

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.20-1.2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.20-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Tue Mar 14 2017 Paul Wouters <pwouters@redhat.com> - 3.20-1
- Updated to 3.20

* Fri Mar 03 2017 Paul Wouters <pwouters@redhat.com> - 3.20-0.1.dr4
- Update to 3.20dr4 to test mozbz#1336487 export CERT_CompareAVA

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.19-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Fri Feb 03 2017 Paul Wouters <pwouters@redhat.com> - 3.19-2
- Resolves: rhbz#1392191 libreswan: crash when OSX client connects
- Improved uniqueid and session replacing support
- Test Buffer warning fix on size_t
- Re-introduce --configdir for backwards compatibility

* Sun Jan 15 2017 Paul Wouters <pwouters@redhat.com> - 3.19-1
- Updated to 3.19 (see download.libreswan.org/CHANGES)

* Mon Dec 19 2016 Miro Hrončok <mhroncok@redhat.com> - 3.18-1.1
- Rebuild for Python 3.6

* Fri Jul 29 2016 Paul Wouters <pwouters@redhat.com> - 3.18-1
- Updated to 3.18 for CVE-2016-5391 rhbz#1361164 and VTI support
- Remove support for /etc/sysconfig/pluto (use native systemd instead)

* Thu May 05 2016 Paul Wouters <pwouters@redhat.com> - 3.17-2
- Resolves: rhbz#1324956 prelink is gone, /etc/prelink.conf.d/* is no longer used 

* Thu Apr 07 2016 Paul Wouters <pwouters@redhat.com> - 3.17-1
- Updated to 3.17 for CVE-2016-3071
- Disable LIBCAP_NG as it prevents unbound-control from working properly
- Temporarilly disable WERROR due to a few minor known issues

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 3.16-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Fri Dec 18 2015 Paul Wouters <pwouters@redhat.com> - 3.16-1
- Updated to 3.16 (see https://download.libreswan.org/CHANGES)

* Tue Aug 11 2015 Paul Wouters <pwouters@redhat.com> - 3.15-1
- Updated to 3.15 (see http://download.libreswan.org/CHANGES)
- Resolves: rhbz#CVE-2015-3240 IKE daemon restart when receiving a bad DH gx
- NSS database creation moved from spec file to service file
- Run CAVS tests on package build
- Added BuildRequire systemd-units and xmlto
- Bumped minimum required nss to 3.16.1
- Install tmpfiles
- Install sysctl file
- Update doc files to include

* Mon Jul 13 2015 Paul Wouters <pwouters@redhat.com> - 3.13-2
- Resolves: rhbz#1238967 Switch libreswan to use python3

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.13-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Mon Jun 01 2015 Paul Wouters <pwouters@redhat.com> - 3.13-1
- Updated to 3.13 for CVE-2015-3204

* Fri Nov 07 2014 Paul Wouters <pwouters@redhat.com> - 3.12-1
- Updated to 3.12 Various IKEv2 fixes

* Wed Oct 22 2014 Paul Wouters <pwouters@redhat.com> - 3.11-1
- Updated to 3.11 (many fixes, including startup fixes)
- Resolves: rhbz#1144941 libreswan 3.10 upgrade breaks old ipsec.secrets configs
- Resolves: rhbz#1147072 ikev1 aggr mode connection fails after libreswan upgrade
- Resolves: rhbz#1144831 Libreswan appears to start with systemd before all the NICs are up and running

* Tue Sep 09 2014 Paul Wouters <pwouters@redhat.com> - 3.10-3
- Fix some coverity issues, auto=route on bootup and snprintf on 32bit machines

* Mon Sep 01 2014 Paul Wouters <pwouters@redhat.com> - 3.10-1
- Updated to 3.10, major bugfix release, new xauth status options

* Sun Aug 17 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.9-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Thu Jul 10 2014 Paul Wouters <pwouters@redhat.com> - 3.9-1
- Updated to 3.9. IKEv2 enhancements, ESP/IKE algo enhancements
- Mark libreswan-fips.conf as config file
- attr modifier for man pages no longer needed
- BUGS file no longer exists upstream

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.8-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Sat Jan 18 2014 Paul Wouters <pwouters@redhat.com> - 3.8-1
- Updated to 3.8, fixes rhbz#CVE-2013-6467 (rhbz#1054102)

* Wed Dec 11 2013 Paul Wouters <pwouters@redhat.com> - 3.7-1
- Updated to 3.7, fixes CVE-2013-4564
- Fixes creating a bogus NSS db on startup (rhbz#1005410)

* Thu Oct 31 2013 Paul Wouters <pwouters@redhat.com> - 3.6-1
- Updated to 3.6 (IKEv2, MODECFG, Cisco interop fixes)
- Generate empty NSS db if none exists

* Mon Aug 19 2013 Paul Wouters <pwouters@redhat.com> - 3.5-3
- Add a Provides: for openswan-doc

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.5-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Mon Jul 15 2013 Paul Wouters <pwouters@redhat.com> - 3.5-2
- Added interop patch for (some?) Cisco VPN clients sending 16 zero
  bytes of extraneous IKE data
- Removed fipscheck_version

* Sat Jul 13 2013 Paul Wouters <pwouters@redhat.com> - 3.5-1
- Updated to 3.5

* Thu Jun 06 2013 Paul Wouters <pwouters@redhat.com> - 3.4-1
- Updated to 3.4, which only contains style changes to kernel coding style
- IN MEMORIAM: June 3rd, 2013 Hugh Daniel

* Mon May 13 2013 Paul Wouters <pwouters@redhat.com> - 3.3-1
- Updated to 3.3, which resolves CVE-2013-2052

* Sat Apr 13 2013 Paul Wouters <pwouters@redhat.com> - 3.2-1
- Initial package for Fedora
