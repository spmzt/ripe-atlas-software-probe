PORTNAME=	ripe-atlas-probe
DISTVERSION=	5130
CATEGORIES=	net-mgmt

MAINTAINER=	pouria@FreeBSD.org
COMMENT=	RIPE Atlas software probe
WWW=		https://github.com/RIPE-NCC/ripe-atlas-software-probe

LICENSE=	GPLv3
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		autoreconf gmake libtool:build ssl
USE_GITHUB=	yes
GH_ACCOUNT=	RIPE-NCC
GH_PROJECT=	ripe-atlas-software-probe

GNU_CONFIGURE=	yes
CONFIGURE_ARGS=	--disable-chown \
		--disable-systemd \
		--with-group=ripe-atlas \
		--with-measurement-user=ripe-atlas-measurement \
		--with-user=ripe-atlas

USERS=		ripe-atlas ripe-atlas-measurement
GROUPS=		ripe-atlas

SUB_FILES=	pkg-message

post-install:
	${RM} -r ${STAGEDIR}/var/run
	${MV} ${STAGEDIR}${PREFIX}/etc/ripe-atlas/mode \
		${STAGEDIR}${PREFIX}/etc/ripe-atlas/mode.sample

.include <bsd.port.mk>
