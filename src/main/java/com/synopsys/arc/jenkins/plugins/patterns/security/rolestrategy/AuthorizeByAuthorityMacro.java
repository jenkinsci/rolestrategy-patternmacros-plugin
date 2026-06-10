/*
 * The MIT License
 *
 * Copyright 2013 Oleg Nenashev, Synopsys Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.synopsys.arc.jenkins.plugins.patterns.security.rolestrategy;

import com.michelin.cio.hudson.plugins.rolestrategy.PermissionEntry;
import com.synopsys.arc.jenkins.plugins.rolestrategy.Macro;
import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleMacroExtension;
import com.synopsys.arc.jenkins.plugins.rolestrategy.RoleType;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.AccessControlled;
import hudson.security.Permission;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import jenkins.model.Jenkins;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * A macro that use regular expression patterns to auto assign roles
 * to groups or users based on their authorities (claims)
 *
 * @author Jean pierre Brunod
 */
@Extension
public final class AuthorizeByAuthorityMacro extends RoleMacroExtension {

  public static String separator = "_";

  private enum PatternType {
    TEMPLATE_PATTERN, PATTERN_TEMPLATE;

    @Override
    public String toString() {
      switch (this) {
        case TEMPLATE_PATTERN:
          return "(?<template>.+)_(?<pattern>.+)";
        case PATTERN_TEMPLATE:
          return "(?<pattern>.+)_(?<template>.+)";
        default:
          throw new IllegalArgumentException("Unknown pattern type");
      }

    }
  }

  private static final Logger LOGGER = Logger.getLogger(AuthorizeByAuthorityMacro.class.getName());

  @Override
  public String getName() {
    return "AuthorizeByAuthority";
  }

  @SuppressFBWarnings(value = "NM_METHOD_NAMING_CONVENTION", justification = "Old code, should be fixed later")
  @Override
  public boolean IsApplicable(RoleType roleType) {
    return roleType == RoleType.Project;
  }

  /**
   * New API method with PermissionEntry.
   * Extracts SID from PermissionEntry and delegates to the old method.
   */
  @Override
  public boolean hasPermission(PermissionEntry entry, Permission p, RoleType type, AccessControlled item, Macro macro) {
    // Extract SID from PermissionEntry
    // Check for null entry first
    if (entry == null) {
      return false;
    }

    String sid = entry.getSid();
    // Check for null or empty SID - deny access in such cases
    if (sid == null || sid.trim().isEmpty()) {
      return false;
    }

    return hasPermission(sid, p, type, item, macro);
  }

  @Override
  public boolean hasPermission(String sid, Permission p, RoleType type, AccessControlled item, Macro macro) {

    if (sid == null || sid.trim().isEmpty()) {
      return false;
    }

    // Retrieve user information and authorities
    User user = User.current();
    Authentication authentication = Jenkins.getAuthentication2();

    String[] parameters = macro.getParameters();

    try {

      // Check for null
      if (user != null && parameters.length >= 2) {

        // Fetch pattern style and use it to create the match
        PatternType pattern = PatternType.valueOf(parameters[1].trim());
        Pattern rx = Pattern.compile(pattern.toString());
        
        for (GrantedAuthority a : authentication.getAuthorities()) {

          String auth = a.getAuthority();

          LOGGER.fine("[" + user.getFullName() + "] trying match on authority: " + auth);
          Matcher m = rx.matcher(auth);

          if (m.find()) {
            String itemPattern = m.group("pattern");

            LOGGER.fine("[" + user.getFullName() + "] matched pattern: " + itemPattern);

            // Prepare a new match for the AccessControlledItem
            Pattern sx = Pattern.compile(itemPattern);
            Matcher s = sx.matcher(((Item) item).getName());

            // Match item pattern and level
            if (s.find() && m.group("template").equals(parameters[0])) {
              LOGGER.fine("[" + user.getFullName() + "] matched item pattern /" + itemPattern + "/ and template " + parameters[0]);
              return true;
            }
          }
        }
      }

    } catch (PatternSyntaxException e) {
      LOGGER.severe("Invalid Regexp Pattern: " + parameters[1]);
    } catch (IllegalArgumentException e) {
      LOGGER.severe("No authorities for user?" + e.getMessage());
    }

    return false;

  }

  @Override
  public String getDescription() {
    return "Auto assign permissions based on user authorities.<br/>"
        + "First parameter is the level for the user, second is the pattern style<br/>"
        + "to use against the available user authorities<br/>"
        + "Available pattern styles:<br/>"
        + "TEMPLATE_PATTERN (ex. viewer_mypipeline)<br/>"
        + "PATTERN_TEMPLATE (ex. mypipeline_viewer)<br/>"
        + "So if you create a Permission Template named 'viewer' and give the user an authority of 'example_viewer',<br/>"
        + "and use a Macro like @AuthorizeByAuthority(viewer, TEMPLATE_PATTERN),<br/>"
        + "the user will be assigned the 'viewer' permission template on pipelines names matching /example/ pattern.<br/>";
  }
}
