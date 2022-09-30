%global _hardened_build 1
# These are rpm macros and are 0 or 1
%global with_efence 0
%global with_development 0
%global with_cavstests 1
# Libreswan config options
%global libreswan_config \\\
    FINALLIBEXECDIR=%{_libexecdir}/ipsec \\\
    FINALMANDIR=%{_mandir} \\\
    FIPSPRODUCTCHECK=%{_sysconfdir}/system-fips \\\
    INC_RCDEFAULT=%{_initrddir} \\\
    INC_USRLOCAL=%{_prefix} \\\
    INITSYSTEM=systemd \\\
    NSS_REQ_AVA_COPY=false \\\
    USE_DNSSEC=true \\\
    USE_FIPSCHECK=true \\\
    USE_LABELED_IPSEC=true \\\
    USE_LDAP=true \\\
    USE_LIBCAP_NG=true \\\
    USE_LIBCURL=true \\\
    USE_LINUX_AUDIT=true \\\
    USE_NM=true \\\
    USE_SECCOMP=true \\\
    USE_XAUTHPAM=true \\\
%{nil}


#global prever rc1

Name: libreswan
Summary: IPsec implementation with IKEv1 and IKEv2 keying protocols
# version is generated in the release script
Version: 3.26
Release: %{?prever:0.}1.3%{?prever:.%{prever}}%{?dist}
License: GPLv2
Url: https://libreswan.org/
Source0: https://download.libreswan.org/%{?prever:with_development/}%{name}-%{version}%{?prever}.tar.gz
%if 0%{with_cavstests}
Source1: https://download.libreswan.org/cavs/ikev1_dsa.fax.bz2
Source2: https://download.libreswan.org/cavs/ikev1_psk.fax.bz2
Source3: https://download.libreswan.org/cavs/ikev2.fax.bz2
%endif

Patch1: libreswan-3.26-asn1-zu.patch

Group: System Environment/Daemons
BuildRequires: bison flex pkgconfig
BuildRequires: gcc
BuildRequires: systemd systemd-units systemd-devel
Requires(post): coreutils bash systemd
Requires(preun): systemd
Requires(postun): systemd

Conflicts: openswan < %{version}-%{release}
Obsoletes: openswan < %{version}-%{release}
Provides: openswan = %{version}-%{release}
Provides: openswan-doc = %{version}-%{release}

BuildRequires: pkgconfig hostname
BuildRequires: nss-devel >= 3.16.1, nspr-devel
BuildRequires: pam-devel
BuildRequires: libevent-devel
BuildRequires: unbound-devel >= 1.6.0-6 ldns-devel
BuildRequires: libseccomp-devel
BuildRequires: libselinux-devel
BuildRequires: fipscheck-devel
Requires: fipscheck%{_isa}
Buildrequires: audit-libs-devel

BuildRequires: libcap-ng-devel
BuildRequires: openldap-devel curl-devel
%if 0%{with_efence}
BuildRequires: ElectricFence
%endif
BuildRequires: xmlto

Requires: nss-tools, nss-softokn
Requires: iproute >= 2.6.8
Requires: unbound-libs >= 1.6.6

%description
Libreswan is a free implementation of IPsec & IKE for Linux.  IPsec is
the Internet Protocol Security and uses strong cryptography to provide
both authentication and encryption services.  These services allow you
to build secure tunnels through untrusted networks.  Everything passing
through the untrusted net is encrypted by the ipsec gateway machine and
decrypted by the gateway at the other end of the tunnel.  The resulting
tunnel is a virtual private network or VPN.

This package contains the daemons and userland tools for setting up
Libreswan. To build KLIPS, see the kmod-libreswan.spec file.

Libreswan also supports IKEv2 (RFC7296) and Secure Labeling

Libreswan is based on Openswan-2.6.38 which in turn is based on FreeS/WAN-2.04

%prep
%setup -q -n libreswan-%{version}%{?prever}
#pathfix.py -i %{__python3} -pn programs/verify/verify.in programs/show/show.in \
#  testing/cert_verify/usage_test testing/pluto/ikev1-01-fuzzer/cve-2015-3204.py \
#  testing/pluto/ikev2-15-fuzzer/send_bad_packets.py testing/x509/dist_certs.py \
#  programs/_unbound-hook/_unbound-hook.in

# linking to freebl is not needed
sed -i "s/-lfreebl //" mk/config.mk

%patch1 -p1

# enable crypto-policies support
sed -i "s:#[ ]*include \(.*\)\(/crypto-policies/back-ends/libreswan.config\)$:include \1\2:" programs/configs/ipsec.conf.in

%build
%if 0%{with_efence}
%global efence "-lefence"
%endif

#796683: -fno-strict-aliasing
make %{?_smp_mflags} \
%if 0%{with_development}
   USERCOMPILE="-g -DGCC_LINT %(echo %{optflags} | sed -e s/-O[0-9]*/ /) %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%else
  USERCOMPILE="-g -DGCC_LINT %{optflags} %{?efence} -fPIE -pie -fno-strict-aliasing -Wformat-nonliteral -Wformat-security" \
%endif
  USERLINK="-g -pie -Wl,-z,relro,-z,now %{?efence}" \
  %{libreswan_config} \
  programs
FS=$(pwd)

# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
  fipshmac -d %{buildroot}%{_libdir}/fipscheck %{buildroot}%{_libexecdir}/ipsec/pluto \
%{nil}

%install
make \
  DESTDIR=%{buildroot} \
  %{libreswan_config} \
  install
FS=$(pwd)
rm -rf %{buildroot}/usr/share/doc/libreswan

install -d -m 0755 %{buildroot}%{_rundir}/pluto
# used when setting --perpeerlog without --perpeerlogbase
install -d -m 0700 %{buildroot}%{_localstatedir}/log/pluto/peer
install -d %{buildroot}%{_sbindir}

install -d %{buildroot}%{_sysconfdir}/sysctl.d
install -m 0644 packaging/fedora/libreswan-sysctl.conf \
  %{buildroot}%{_sysconfdir}/sysctl.d/50-libreswan.conf

install -d %{buildroot}%{_tmpfilesdir}
install -m 0644 packaging/fedora/libreswan-tmpfiles.conf  \
  %{buildroot}%{_tmpfilesdir}/libreswan.conf

mkdir -p %{buildroot}%{_libdir}/fipscheck

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
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto
%attr(0700,root,root) %dir %{_localstatedir}/log/pluto/peer
%attr(0755,root,root) %dir %{_rundir}/pluto
%attr(0644,root,root) %{_tmpfilesdir}/libreswan.conf
%attr(0644,root,root) %{_unitdir}/ipsec.service
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pam.d/pluto
%{_sbindir}/ipsec
%{_libexecdir}/ipsec
%attr(0644,root,root) %doc %{_mandir}/*/*
%{_libdir}/fipscheck/pluto.hmac

%changelog
* Fri Sep 30 2022 Samuel Verschelde <stormi-xcp@ylix.fr> - 3.26-1.3
- Rebuild for XCP-ng 8.3 alpha

* Thu Jul 02 2020 Samuel Verschelde <stormi-xcp@ylix.fr> - 3.26-1.2
- Rebuild for XCP-ng 8.2

* Fri Dec 20 2019 Samuel Verschelde <stormi-xcp@ylix.fr> - 3.26-1.1
- Rebuild for XCP-ng 8.1

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
