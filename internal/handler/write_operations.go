package handler

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"

	"github.com/glauth/ldap"
	zclient "github.com/jacobalberty/zitadel-ldap/internal/zitadel"
)

// processLDAPAttributes maps LDAP attributes to Zitadel user update request fields
func (z *zitadelHandler) processLDAPAttributes(attrType string, attrVals []string, updateReq *zclient.UserUpdateRequest) {
	if len(attrVals) == 0 {
		return
	}
	value := attrVals[0]

	switch strings.ToLower(attrType) {
	case "givenname":
		updateReq.GivenName = &value
	case "sn", "surname":
		updateReq.FamilyName = &value
	case "mail", "email":
		updateReq.Email = &value
	case "userpassword":
		updateReq.Password = &value
	case "displayname":
		updateReq.DisplayName = &value
	case "nickname":
		updateReq.NickName = &value
	case "preferredlanguage":
		updateReq.PreferredLanguage = &value
	case "telephonenumber", "phone":
		updateReq.Phone = &value
	default:
		// Store other attributes as metadata with "gl_" prefix
		if strings.HasPrefix(strings.ToLower(attrType), "gl_") ||
			!strings.HasPrefix(strings.ToLower(attrType), "object") {
			key := "gl_" + strings.ToLower(attrType)
			updateReq.Metadata[key] = []byte(value)
		}
	}
}

// processCreateAttributes maps LDAP attributes to create user request
func (z *zitadelHandler) processCreateAttributes(attrType string, attrVals []string, createReq *zclient.UserCreateRequest) {
	if len(attrVals) == 0 {
		return
	}
	value := attrVals[0]

	switch strings.ToLower(attrType) {
	case "givenname":
		createReq.GivenName = value
	case "sn", "surname":
		createReq.FamilyName = value
	case "mail", "email":
		createReq.Email = value
	case "userpassword":
		createReq.Password = value
	case "displayname":
		createReq.DisplayName = value
	case "nickname":
		createReq.NickName = value
	case "preferredlanguage":
		createReq.PreferredLanguage = value
	case "telephonenumber", "phone":
		createReq.Phone = value
	default:
		// Store other attributes as metadata with "gl_" prefix
		if strings.HasPrefix(strings.ToLower(attrType), "gl_") ||
			!strings.HasPrefix(strings.ToLower(attrType), "object") {
			key := "gl_" + strings.ToLower(attrType)
			createReq.Metadata[key] = []byte(value)
		}
	}
}

// extractAddRequestFields reads the unexported fields of ldap.AddRequest via
// reflection. It deliberately never calls Interface() on the values: that
// panics for values obtained through unexported fields. String()/Len()/Index()
// are permitted on them.
func (z *zitadelHandler) extractAddRequestFields(req ldap.AddRequest) (string, []reflect.Value, error) {
	v := reflect.ValueOf(req)
	dnVal := v.FieldByName("dn")
	if !dnVal.IsValid() || dnVal.Kind() != reflect.String {
		return "", nil, fmt.Errorf("cannot access DN from AddRequest")
	}
	dn := dnVal.String()

	attrsVal := v.FieldByName("attributes")
	if !attrsVal.IsValid() || attrsVal.Kind() != reflect.Slice {
		return dn, nil, fmt.Errorf("cannot access attributes from AddRequest")
	}

	attrs := make([]reflect.Value, 0, attrsVal.Len())
	for i := 0; i < attrsVal.Len(); i++ {
		attrs = append(attrs, attrsVal.Index(i))
	}

	return dn, attrs, nil
}

// getAttributeTypeAndVals extracts type and values from a reflected Attribute.
func (z *zitadelHandler) getAttributeTypeAndVals(attr reflect.Value) (string, []string) {
	attr = reflect.Indirect(attr)
	if attr.Kind() != reflect.Struct {
		return "", nil
	}
	typeField := attr.FieldByName("attrType")
	valsField := attr.FieldByName("attrVals")
	if !typeField.IsValid() || typeField.Kind() != reflect.String {
		return "", nil
	}

	var vals []string
	if valsField.IsValid() && valsField.Kind() == reflect.Slice {
		for i := 0; i < valsField.Len(); i++ {
			vals = append(vals, valsField.Index(i).String())
		}
	}

	return typeField.String(), vals
}

// Add creates a new LDAP entry (user) in Zitadel
func (z *zitadelHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (code ldap.LDAPResultCode, err error) {
	defer z.recoverOp("Add", &code, &err)

	// Extract DN and attributes
	dn, attrs, err := z.extractAddRequestFields(req)
	if err != nil {
		z.log.Warn().Err(err).Msg("Failed to extract AddRequest fields")
		return ldap.LDAPResultOperationsError, err
	}

	if dn == "" {
		z.log.Warn().Msg("Empty DN in Add request")
		return ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("DN is required")
	}

	username, code, err := z.authorizeWriteTarget(boundDN, dn)
	if err != nil {
		return code, err
	}

	z.log.Info().Str("dn", dn).Msg("Adding user")

	// Build create request
	createReq := &zclient.UserCreateRequest{
		Username: username,
		Metadata: make(map[string][]byte),
	}

	// Process attributes
	for _, attr := range attrs {
		attrType, attrVals := z.getAttributeTypeAndVals(attr)
		z.processCreateAttributes(attrType, attrVals, createReq)
	}

	// Validate required fields
	if createReq.Email == "" {
		z.log.Warn().Str("username", username).Msg("Email is required")
		return ldap.LDAPResultConstraintViolation, fmt.Errorf("email is required")
	}
	if createReq.GivenName == "" || createReq.FamilyName == "" {
		z.log.Warn().Str("username", username).Msg("Given name and family name are required")
		return ldap.LDAPResultConstraintViolation, fmt.Errorf("given name and family name are required")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Create the user
	user, err := z.repository.CreateUser(ctx, createReq)
	if err != nil {
		z.log.Error().Err(err).Str("username", username).Msg("Failed to create user")
		return ldap.LDAPResultOperationsError, fmt.Errorf("failed to create user: %w", err)
	}

	z.log.Info().Str("username", username).Str("userID", user.UserID).Msg("User created successfully")
	return ldap.LDAPResultSuccess, nil
}

// Modify updates an existing LDAP entry (user) in Zitadel
func (z *zitadelHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (code ldap.LDAPResultCode, err error) {
	defer z.recoverOp("Modify", &code, &err)

	dn := req.Dn
	if dn == "" {
		z.log.Warn().Msg("Empty DN in Modify request")
		return ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("DN is required")
	}

	username, code, err := z.authorizeWriteTarget(boundDN, dn)
	if err != nil {
		return code, err
	}

	z.log.Info().Str("dn", dn).Msg("Modifying user")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Find user to get their ID
	userResults, err := z.repository.FindUserByName(ctx, username)
	if err != nil {
		z.log.Error().Err(err).Str("username", username).Msg("Failed to find user")
		return ldap.LDAPResultOperationsError, fmt.Errorf("failed to find user: %w", err)
	}
	if len(userResults.Result) == 0 {
		z.log.Warn().Str("username", username).Msg("User not found")
		return ldap.LDAPResultNoSuchObject, fmt.Errorf("user not found: %s", username)
	}

	user := userResults.Result[0]

	// Build update request from modifications
	updateReq := &zclient.UserUpdateRequest{
		Metadata: make(map[string][]byte),
	}

	// Process add and replace attributes
	for _, attr := range req.AddAttributes {
		z.processLDAPAttributes(attr.AttrType, attr.AttrVals, updateReq)
	}
	for _, attr := range req.ReplaceAttributes {
		z.processLDAPAttributes(attr.AttrType, attr.AttrVals, updateReq)
	}

	// Update the user
	err = z.repository.UpdateUser(ctx, user.UserID, updateReq)
	if err != nil {
		z.log.Error().Err(err).Str("username", username).Msg("Failed to modify user")
		return ldap.LDAPResultOperationsError, fmt.Errorf("failed to modify user: %w", err)
	}

	z.log.Info().Str("username", username).Str("userID", user.UserID).Msg("User modified successfully")
	return ldap.LDAPResultSuccess, nil
}

// Delete removes an existing LDAP entry (user) from Zitadel
func (z *zitadelHandler) Delete(boundDN, deleteDN string, conn net.Conn) (code ldap.LDAPResultCode, err error) {
	defer z.recoverOp("Delete", &code, &err)

	if deleteDN == "" {
		z.log.Warn().Msg("Empty DN in Delete request")
		return ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("DN is required")
	}

	username, code, err := z.authorizeWriteTarget(boundDN, deleteDN)
	if err != nil {
		return code, err
	}

	z.log.Info().Str("dn", deleteDN).Msg("Deleting user")

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	// Find user to get their ID
	userResults, err := z.repository.FindUserByName(ctx, username)
	if err != nil {
		z.log.Error().Err(err).Str("username", username).Msg("Failed to find user")
		return ldap.LDAPResultOperationsError, fmt.Errorf("failed to find user: %w", err)
	}
	if len(userResults.Result) == 0 {
		z.log.Warn().Str("username", username).Msg("User not found")
		return ldap.LDAPResultNoSuchObject, fmt.Errorf("user not found: %s", username)
	}

	user := userResults.Result[0]

	// Delete the user
	err = z.repository.DeleteUser(ctx, user.UserID)
	if err != nil {
		z.log.Error().Err(err).Str("username", username).Msg("Failed to delete user")
		return ldap.LDAPResultOperationsError, fmt.Errorf("failed to delete user: %w", err)
	}

	z.log.Info().Str("username", username).Str("userID", user.UserID).Msg("User deleted successfully")
	return ldap.LDAPResultSuccess, nil
}

// authorizeWriteTarget checks that boundDN may write and that targetDN is a
// user entry directly under ou=users,<baseDN>. It returns the user name.
func (z *zitadelHandler) authorizeWriteTarget(boundDN, targetDN string) (string, ldap.LDAPResultCode, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if code, err := z.authorizeWrite(ctx, boundDN); err != nil {
		return "", code, err
	}

	username, err := z.usernameFromDN(targetDN)
	if err != nil {
		z.log.Warn().Err(err).Str("dn", targetDN).Msg("Rejected write target DN")
		return "", ldap.LDAPResultInvalidDNSyntax, fmt.Errorf("invalid DN: %s", targetDN)
	}

	return username, ldap.LDAPResultSuccess, nil
}
