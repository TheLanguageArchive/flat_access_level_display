<?xml version="1.0" encoding="UTF-8"?>
<xsl:include href="/var/www/fedora/tomcat/webapps/fedoragsearch/WEB-INF/classes/fgsconfigFinal/index/FgsIndex/islandora_transforms/compound-children.xslt"/>

<xsl:variable name="compound_children">
    <xsl:call-template name="get-compound-children">
        <xsl:with-param name="PID" select="$PID"/>
    </xsl:call-template>
</xsl:variable>

<xsl:for-each select="xalan:nodeset($compound_children)//sparql:obj[@uri != concat('info:fedora/', $PID)]">
    <field name="compound_children_ms"><xsl:value-of select="substring-after(@uri, '/')"/></field>
</xsl:for-each>

<xsl:for-each select="xalan:nodeset($compound_children)//sparql:obj[@uri != concat('info:fedora/', $PID)]">
    <xsl:variable name="child_pid" select="substring-after(@uri, '/')"/>
    <xsl:variable name="child_policy" select="document(concat($PROT, '://', encoder:encode($FEDORAUSER), ':', encoder:encode($FEDORAPASS), '@', $HOST, ':', $PORT, '/fedora/objects/', $child_pid, '/datastreams/POLICY/content'))"/>
    <xsl:for-each select="xalan:nodeset($child_policy)/node()/node()[@RuleId = 'deny-dsid-mime']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:subject:loginId']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
        <field name="compound_policy_datastream_children_users_ms">
            <xsl:value-of select="normalize-space(.)"/>
        </field>
    </xsl:for-each>
    <xsl:variable name="compound_policy_datastream_children_roles" select="xalan:nodeset($child_policy)/node()/node()[@RuleId = 'deny-dsid-mime']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'fedoraRole']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']"/>
    <field name="compound_policy_datastream_children_roles_ms">
        <xsl:value-of select="$compound_policy_datastream_children_roles"/>
    </field>
    <field name="compound_policy_datastream_children_access_levels_ms">
        <xsl:if test="contains($compound_policy_datastream_children_roles, 'anonymous user')">
            <xsl:text>public</xsl:text>
        </xsl:if>
        <xsl:if test="contains($compound_policy_datastream_children_roles, 'authenticated user')">
            <xsl:text>authenticated</xsl:text>
        </xsl:if>
        <xsl:if test="contains($compound_policy_datastream_children_roles, 'academic user')">
            <xsl:text>academic</xsl:text>
        </xsl:if>
        <xsl:if test="not(contains($compound_policy_datastream_children_roles, 'anonymous user')) and not(contains($compound_policy_datastream_children_roles, 'authenticated user')) and not(contains($compound_policy_datastream_children_roles, 'academic user'))">
            <xsl:text>restricted</xsl:text>
        </xsl:if>
    </field>
</xsl:for-each>
<xsl:for-each select="//foxml:datastream[@ID = 'POLICY']/foxml:datastreamVersion[last()]/foxml:xmlContent">
    <xsl:choose>
        <xsl:when test="node()/node()[@RuleId = 'deny-dsid-mime']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:subject:loginId']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
            <xsl:for-each select="node()/node()[@RuleId = 'deny-dsid-mime']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:subject:loginId']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
                <field name="policy_datastream_users_ms">
                    <xsl:value-of select="normalize-space(.)"/>
                </field>
            </xsl:for-each>
        </xsl:when>
    </xsl:choose>
</xsl:for-each>
<xsl:for-each select="//foxml:datastream[@ID = 'POLICY']/foxml:datastreamVersion[last()]/foxml:xmlContent">
    <xsl:choose>
        <xsl:when test="node()/node()[@RuleId = 'deny-dsid-mime']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'fedoraRole']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
            <xsl:for-each select="node()/node()[@RuleId = 'deny-dsid-mime']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'fedoraRole']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
                <field name="policy_datastream_roles_ms">
                    <xsl:value-of select="normalize-space(.)"/>
                </field>
            </xsl:for-each>
        </xsl:when>
    </xsl:choose>
</xsl:for-each>
<xsl:for-each select="//foxml:datastream[@ID = 'POLICY']/foxml:datastreamVersion[last()]/foxml:xmlContent">
    <xsl:choose>
        <xsl:when test="node()/node()[@RuleId = 'deny-management-functions']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:subject:loginId']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
            <xsl:for-each select="node()/node()[@RuleId = 'deny-management-functions']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:subject:loginId']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
                <field name="policy_management_users_ms">
                    <xsl:value-of select="normalize-space(.)"/>
                </field>
            </xsl:for-each>
        </xsl:when>
    </xsl:choose>
</xsl:for-each>
<xsl:for-each select="//foxml:datastream[@ID = 'POLICY']/foxml:datastreamVersion[last()]/foxml:xmlContent">
    <xsl:choose>
        <xsl:when test="node()/node()[@RuleId = 'deny-management-functions']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'fedoraRole']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
            <xsl:for-each select="node()/node()[@RuleId = 'deny-management-functions']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:not']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:or']/node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-at-least-one-member-of']/node()[@AttributeId = 'fedoraRole']/following-sibling::node()[@FunctionId = 'urn:oasis:names:tc:xacml:1.0:function:string-bag']/node()['AttributeValue'][normalize-space()!='']">
                <field name="policy_management_roles_ms">
                    <xsl:value-of select="normalize-space(.)"/>
                </field>
            </xsl:for-each>
        </xsl:when>
    </xsl:choose>
</xsl:for-each>
<xsl:for-each select="//foxml:datastream[@ID = 'POLICY']/foxml:datastreamVersion[last()]/foxml:xmlContent">
    <xsl:choose>
        <xsl:when test="node()/node()[@RuleId = 'deny-dsid-mime']/node()['Target']/node()['Resources']/node()['Resource']/node()/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:resource:datastream:mimeType']/preceding-sibling::node()['AttributeValue'][normalize-space()!='']">
            <xsl:for-each select="node()/node()[@RuleId = 'deny-dsid-mime']/node()['Target']/node()['Resources']/node()['Resource']/node()/node()[@AttributeId = 'urn:fedora:names:fedora:2.1:resource:datastream:mimeType']/preceding-sibling::node()['AttributeValue'][normalize-space()!='']">
                <field name="policy_datastream_types_ms">
                    <xsl:value-of select="normalize-space(.)"/>
                </field>
            </xsl:for-each>
        </xsl:when>
    </xsl:choose>
</xsl:for-each>
