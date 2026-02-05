package unifi

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/ubiquiti-community/go-unifi/unifi"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ resource.Resource                = &firewallPolicyResource{}
	_ resource.ResourceWithImportState = &firewallPolicyResource{}
)

func NewFirewallPolicyResource() resource.Resource {
	return &firewallPolicyResource{}
}

// firewallPolicyResource defines the resource implementation.
type firewallPolicyResource struct {
	client *Client
}

// firewallPolicyResourceModel describes the resource data model.
type firewallPolicyResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Site        types.String `tfsdk:"site"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Index       types.Int64  `tfsdk:"index"`

	Action              types.String `tfsdk:"action"`
	IPVersion           types.String `tfsdk:"ip_version"`
	Protocol            types.String `tfsdk:"protocol"`
	ConnectionStateType types.String `tfsdk:"connection_state_type"`
	Logging             types.Bool   `tfsdk:"logging"`

	Source      types.Object `tfsdk:"source"`
	Destination types.Object `tfsdk:"destination"`
	Schedule    types.Object `tfsdk:"schedule"`
}

// firewallPolicyEndpointModel represents source or destination.
type firewallPolicyEndpointModel struct {
	ZoneID             types.String `tfsdk:"zone_id"`
	MatchingTarget     types.String `tfsdk:"matching_target"`
	MatchingTargetType types.String `tfsdk:"matching_target_type"`
	IPs                types.Set    `tfsdk:"ips"`
	NetworkIDs         types.Set    `tfsdk:"network_ids"`
	Port               types.Int64  `tfsdk:"port"`
	PortMatchingType   types.String `tfsdk:"port_matching_type"`
	PortGroupID        types.String `tfsdk:"port_group_id"`
}

// firewallPolicyScheduleModel represents the schedule block.
type firewallPolicyScheduleModel struct {
	Mode           types.String `tfsdk:"mode"`
	Date           types.String `tfsdk:"date"`
	RepeatOnDays   types.Set    `tfsdk:"repeat_on_days"`
	TimeAllDay     types.Bool   `tfsdk:"time_all_day"`
	TimeRangeStart types.String `tfsdk:"time_range_start"`
	TimeRangeEnd   types.String `tfsdk:"time_range_end"`
}

// Attribute types for nested objects
var firewallPolicyEndpointAttrTypes = map[string]attr.Type{
	"zone_id":              types.StringType,
	"matching_target":      types.StringType,
	"matching_target_type": types.StringType,
	"ips":                  types.SetType{ElemType: types.StringType},
	"network_ids":          types.SetType{ElemType: types.StringType},
	"port":                 types.Int64Type,
	"port_matching_type":   types.StringType,
	"port_group_id":        types.StringType,
}

var firewallPolicyScheduleAttrTypes = map[string]attr.Type{
	"mode":             types.StringType,
	"date":             types.StringType,
	"repeat_on_days":   types.SetType{ElemType: types.StringType},
	"time_all_day":     types.BoolType,
	"time_range_start": types.StringType,
	"time_range_end":   types.StringType,
}

func (r *firewallPolicyResource) Metadata(
	ctx context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_policy"
}

func (r *firewallPolicyResource) Schema(
	ctx context.Context,
	req resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	endpointBlockAttrs := map[string]schema.Attribute{
		"zone_id": schema.StringAttribute{
			MarkdownDescription: "The ID of the firewall zone.",
			Required:            true,
		},
		"matching_target": schema.StringAttribute{
			MarkdownDescription: "The matching target type. One of: `ANY`, `DEVICE`, `IP`, `NETWORK`, `MAC`.",
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString("ANY"),
			Validators: []validator.String{
				stringvalidator.OneOf("ANY", "DEVICE", "IP", "NETWORK", "MAC"),
			},
		},
		"matching_target_type": schema.StringAttribute{
			MarkdownDescription: "The matching target specification type. One of: `ANY`, `SPECIFIC`, `LIST`, `OBJECT`.",
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString("ANY"),
			Validators: []validator.String{
				stringvalidator.OneOf("ANY", "SPECIFIC", "LIST", "OBJECT"),
			},
		},
		"ips": schema.SetAttribute{
			MarkdownDescription: "List of IP addresses or CIDR ranges to match.",
			Optional:            true,
			ElementType:         types.StringType,
		},
		"network_ids": schema.SetAttribute{
			MarkdownDescription: "List of network IDs to match (for NETWORK matching target).",
			Optional:            true,
			ElementType:         types.StringType,
		},
		"port": schema.Int64Attribute{
			MarkdownDescription: "The port number to match.",
			Optional:            true,
		},
		"port_matching_type": schema.StringAttribute{
			MarkdownDescription: "The port matching type. One of: `ANY`, `SPECIFIC`, `LIST`, `OBJECT`.",
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString("ANY"),
			Validators: []validator.String{
				stringvalidator.OneOf("ANY", "SPECIFIC", "LIST", "OBJECT"),
			},
		},
		"port_group_id": schema.StringAttribute{
			MarkdownDescription: "The ID of a port group to match.",
			Optional:            true,
		},
	}

	resp.Schema = schema.Schema{
		MarkdownDescription: "`unifi_firewall_policy` manages Zone-Based Firewall (ZBF) policies. " +
			"These policies control traffic between firewall zones (e.g., External, Internal, DMZ).",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The ID of the firewall policy.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"site": schema.StringAttribute{
				MarkdownDescription: "The name of the site to associate the firewall policy with.",
				Computed:            true,
				Optional:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the firewall policy.",
				Required:            true,
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "A description of the firewall policy.",
				Optional:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the policy is enabled.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"index": schema.Int64Attribute{
				MarkdownDescription: "The order/priority of the policy. Lower numbers are evaluated first.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(10000),
			},
			"action": schema.StringAttribute{
				MarkdownDescription: "The action to take. One of: `ALLOW`, `BLOCK`, `REJECT`.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.OneOf("ALLOW", "BLOCK", "REJECT"),
				},
			},
			"ip_version": schema.StringAttribute{
				MarkdownDescription: "The IP version to match. One of: `BOTH`, `IPV4`, `IPV6`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("BOTH"),
				Validators: []validator.String{
					stringvalidator.OneOf("BOTH", "IPV4", "IPV6"),
				},
			},
			"protocol": schema.StringAttribute{
				MarkdownDescription: "The protocol to match. One of: `all`, `tcp`, `udp`, `tcp_udp`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("all"),
				Validators: []validator.String{
					stringvalidator.OneOf("all", "tcp", "udp", "tcp_udp"),
				},
			},
			"connection_state_type": schema.StringAttribute{
				MarkdownDescription: "The connection state matching type. One of: `ALL`, `RESPOND_ONLY`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("ALL"),
				Validators: []validator.String{
					stringvalidator.OneOf("ALL", "RESPOND_ONLY"),
				},
			},
			"logging": schema.BoolAttribute{
				MarkdownDescription: "Whether to log matching traffic.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
		},
		Blocks: map[string]schema.Block{
			"source": schema.SingleNestedBlock{
				MarkdownDescription: "The source endpoint configuration.",
				Attributes:          endpointBlockAttrs,
			},
			"destination": schema.SingleNestedBlock{
				MarkdownDescription: "The destination endpoint configuration.",
				Attributes:          endpointBlockAttrs,
			},
			"schedule": schema.SingleNestedBlock{
				MarkdownDescription: "The schedule for when this policy is active.",
				Attributes: map[string]schema.Attribute{
					"mode": schema.StringAttribute{
						MarkdownDescription: "The schedule mode. One of: `ALWAYS`, `EVERY_DAY`, `EVERY_WEEK`, `ONE_TIME_ONLY`.",
						Optional:            true,
						Computed:            true,
						Default:             stringdefault.StaticString("ALWAYS"),
						Validators: []validator.String{
							stringvalidator.OneOf("ALWAYS", "EVERY_DAY", "EVERY_WEEK", "ONE_TIME_ONLY"),
						},
					},
					"date": schema.StringAttribute{
						MarkdownDescription: "The date for ONE_TIME_ONLY mode (YYYY-MM-DD format).",
						Optional:            true,
					},
					"repeat_on_days": schema.SetAttribute{
						MarkdownDescription: "Days of the week to repeat. Values: `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`.",
						Optional:            true,
						ElementType:         types.StringType,
					},
					"time_all_day": schema.BoolAttribute{
						MarkdownDescription: "Whether the policy applies all day.",
						Optional:            true,
						Computed:            true,
						Default:             booldefault.StaticBool(true),
					},
					"time_range_start": schema.StringAttribute{
						MarkdownDescription: "Start time in HH:MM format.",
						Optional:            true,
					},
					"time_range_end": schema.StringAttribute{
						MarkdownDescription: "End time in HH:MM format.",
						Optional:            true,
					},
				},
			},
		},
	}
}

func (r *firewallPolicyResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *Client, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	r.client = client
}

func (r *firewallPolicyResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan firewallPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	site := plan.Site.ValueString()
	if site == "" {
		site = r.client.Site
	}

	// Convert model to API request
	firewallPolicy, err := r.modelToAPIFirewallPolicy(ctx, &plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Converting Firewall Policy",
			fmt.Sprintf("Could not convert firewall policy to API format: %s", err),
		)
		return
	}

	apiFirewallPolicy, err := r.client.CreateFirewallPolicy(ctx, site, firewallPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Firewall Policy",
			fmt.Sprintf("Could not create firewall policy: %s", err),
		)
		return
	}

	// Set state
	plan.ID = types.StringValue(apiFirewallPolicy.ID)
	plan.Site = types.StringValue(site)
	r.setResourceData(ctx, apiFirewallPolicy, &plan, site)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *firewallPolicyResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state firewallPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	site := state.Site.ValueString()
	if site == "" {
		site = r.client.Site
	}

	firewallPolicy, err := r.client.GetFirewallPolicy(ctx, site, id)
	if err != nil {
		if _, ok := err.(*unifi.NotFoundError); ok {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error Reading Firewall Policy",
			fmt.Sprintf("Could not read firewall policy %s: %s", id, err),
		)
		return
	}

	// Update state from API response
	r.setResourceData(ctx, firewallPolicy, &state, site)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *firewallPolicyResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan firewallPolicyResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state firewallPolicyResourceModel
	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	site := plan.Site.ValueString()
	if site == "" {
		site = r.client.Site
	}

	id := state.ID.ValueString()

	// Read current firewall policy and merge with planned changes
	currentFirewallPolicy, err := r.client.GetFirewallPolicy(ctx, site, id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Firewall Policy for Update",
			fmt.Sprintf("Could not read firewall policy %s for update: %s", id, err),
		)
		return
	}

	// Apply current API values to state
	r.setResourceData(ctx, currentFirewallPolicy, &state, site)

	// Apply plan changes to the state (merge pattern)
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		state.Name = plan.Name
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		state.Description = plan.Description
	}
	if !plan.Enabled.IsNull() && !plan.Enabled.IsUnknown() {
		state.Enabled = plan.Enabled
	}
	if !plan.Index.IsNull() && !plan.Index.IsUnknown() {
		state.Index = plan.Index
	}
	if !plan.Action.IsNull() && !plan.Action.IsUnknown() {
		state.Action = plan.Action
	}
	if !plan.IPVersion.IsNull() && !plan.IPVersion.IsUnknown() {
		state.IPVersion = plan.IPVersion
	}
	if !plan.Protocol.IsNull() && !plan.Protocol.IsUnknown() {
		state.Protocol = plan.Protocol
	}
	if !plan.ConnectionStateType.IsNull() && !plan.ConnectionStateType.IsUnknown() {
		state.ConnectionStateType = plan.ConnectionStateType
	}
	if !plan.Logging.IsNull() && !plan.Logging.IsUnknown() {
		state.Logging = plan.Logging
	}
	if !plan.Source.IsNull() && !plan.Source.IsUnknown() {
		state.Source = plan.Source
	}
	if !plan.Destination.IsNull() && !plan.Destination.IsUnknown() {
		state.Destination = plan.Destination
	}
	if !plan.Schedule.IsNull() && !plan.Schedule.IsUnknown() {
		state.Schedule = plan.Schedule
	}

	// Convert updated state to API request
	firewallPolicy, err := r.modelToAPIFirewallPolicy(ctx, &state)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Converting Firewall Policy for Update",
			fmt.Sprintf("Could not convert firewall policy to API format: %s", err),
		)
		return
	}

	firewallPolicy.ID = id
	firewallPolicy.SiteID = currentFirewallPolicy.SiteID

	apiFirewallPolicy, err := r.client.UpdateFirewallPolicy(ctx, site, firewallPolicy)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Firewall Policy",
			fmt.Sprintf("Could not update firewall policy %s: %s", id, err),
		)
		return
	}

	// Update state from API response
	r.setResourceData(ctx, apiFirewallPolicy, &state, site)

	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

func (r *firewallPolicyResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state firewallPolicyResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	site := state.Site.ValueString()
	if site == "" {
		site = r.client.Site
	}

	err := r.client.DeleteFirewallPolicy(ctx, site, id)
	if err != nil {
		if _, ok := err.(*unifi.NotFoundError); ok {
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting Firewall Policy",
			fmt.Sprintf("Could not delete firewall policy %s: %s", id, err),
		)
		return
	}
}

func (r *firewallPolicyResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	idParts, diags := ParseImportID(req.ID, 1, 2)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if site := idParts["site"]; site != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("site"), site)...)
	}

	if id := idParts["id"]; id != "" {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	}
}

// Helper methods

func (r *firewallPolicyResource) modelToAPIFirewallPolicy(
	ctx context.Context,
	model *firewallPolicyResourceModel,
) (*unifi.FirewallPolicy, error) {
	policy := &unifi.FirewallPolicy{
		Name:                model.Name.ValueString(),
		Description:         model.Description.ValueString(),
		Enabled:             model.Enabled.ValueBool(),
		Index:               model.Index.ValueInt64(),
		Action:              model.Action.ValueString(),
		IPVersion:           model.IPVersion.ValueString(),
		Protocol:            model.Protocol.ValueString(),
		ConnectionStateType: model.ConnectionStateType.ValueString(),
		Logging:             model.Logging.ValueBool(),
	}

	// Convert source
	if !model.Source.IsNull() && !model.Source.IsUnknown() {
		var sourceModel firewallPolicyEndpointModel
		diags := model.Source.As(ctx, &sourceModel, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, fmt.Errorf("could not convert source")
		}
		policy.Source = r.endpointModelToAPI(ctx, &sourceModel)
	}

	// Convert destination
	if !model.Destination.IsNull() && !model.Destination.IsUnknown() {
		var destModel firewallPolicyEndpointModel
		diags := model.Destination.As(ctx, &destModel, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, fmt.Errorf("could not convert destination")
		}
		policy.Destination = r.endpointModelToAPIDestination(ctx, &destModel)
	}

	// Convert schedule
	if !model.Schedule.IsNull() && !model.Schedule.IsUnknown() {
		var scheduleModel firewallPolicyScheduleModel
		diags := model.Schedule.As(ctx, &scheduleModel, basetypes.ObjectAsOptions{})
		if diags.HasError() {
			return nil, fmt.Errorf("could not convert schedule")
		}
		policy.Schedule = r.scheduleModelToAPI(ctx, &scheduleModel)
	}

	return policy, nil
}

func (r *firewallPolicyResource) endpointModelToAPI(
	ctx context.Context,
	model *firewallPolicyEndpointModel,
) unifi.FirewallPolicySource {
	source := unifi.FirewallPolicySource{
		ZoneID:             model.ZoneID.ValueString(),
		MatchingTarget:     model.MatchingTarget.ValueString(),
		MatchingTargetType: model.MatchingTargetType.ValueString(),
		PortMatchingType:   model.PortMatchingType.ValueString(),
		PortGroupID:        model.PortGroupID.ValueString(),
	}

	if !model.Port.IsNull() && !model.Port.IsUnknown() {
		source.Port = model.Port.ValueInt64()
	}

	if !model.IPs.IsNull() && !model.IPs.IsUnknown() {
		var ips []string
		model.IPs.ElementsAs(ctx, &ips, false)
		source.IPs = ips
	}

	if !model.NetworkIDs.IsNull() && !model.NetworkIDs.IsUnknown() {
		var networkIDs []string
		model.NetworkIDs.ElementsAs(ctx, &networkIDs, false)
		source.NetworkIDs = networkIDs
	}

	return source
}

func (r *firewallPolicyResource) endpointModelToAPIDestination(
	ctx context.Context,
	model *firewallPolicyEndpointModel,
) unifi.FirewallPolicyDestination {
	dest := unifi.FirewallPolicyDestination{
		ZoneID:             model.ZoneID.ValueString(),
		MatchingTarget:     model.MatchingTarget.ValueString(),
		MatchingTargetType: model.MatchingTargetType.ValueString(),
		PortMatchingType:   model.PortMatchingType.ValueString(),
		PortGroupID:        model.PortGroupID.ValueString(),
	}

	if !model.Port.IsNull() && !model.Port.IsUnknown() {
		dest.Port = model.Port.ValueInt64()
	}

	if !model.IPs.IsNull() && !model.IPs.IsUnknown() {
		var ips []string
		model.IPs.ElementsAs(ctx, &ips, false)
		dest.IPs = ips
	}

	if !model.NetworkIDs.IsNull() && !model.NetworkIDs.IsUnknown() {
		var networkIDs []string
		model.NetworkIDs.ElementsAs(ctx, &networkIDs, false)
		dest.NetworkIDs = networkIDs
	}

	return dest
}

func (r *firewallPolicyResource) scheduleModelToAPI(
	ctx context.Context,
	model *firewallPolicyScheduleModel,
) unifi.FirewallPolicySchedule {
	schedule := unifi.FirewallPolicySchedule{
		Mode:           model.Mode.ValueString(),
		Date:           model.Date.ValueString(),
		TimeAllDay:     model.TimeAllDay.ValueBool(),
		TimeRangeStart: model.TimeRangeStart.ValueString(),
		TimeRangeEnd:   model.TimeRangeEnd.ValueString(),
	}

	if !model.RepeatOnDays.IsNull() && !model.RepeatOnDays.IsUnknown() {
		var days []string
		model.RepeatOnDays.ElementsAs(ctx, &days, false)
		schedule.RepeatOnDays = days
	}

	return schedule
}

func (r *firewallPolicyResource) setResourceData(
	ctx context.Context,
	policy *unifi.FirewallPolicy,
	model *firewallPolicyResourceModel,
	site string,
) {
	model.Site = types.StringValue(site)
	model.Name = types.StringValue(policy.Name)
	model.Enabled = types.BoolValue(policy.Enabled)
	model.Index = types.Int64Value(policy.Index)
	model.Action = types.StringValue(policy.Action)
	model.Logging = types.BoolValue(policy.Logging)

	if policy.Description == "" {
		model.Description = types.StringNull()
	} else {
		model.Description = types.StringValue(policy.Description)
	}

	if policy.IPVersion == "" {
		model.IPVersion = types.StringValue("BOTH")
	} else {
		model.IPVersion = types.StringValue(policy.IPVersion)
	}

	if policy.Protocol == "" {
		model.Protocol = types.StringValue("all")
	} else {
		model.Protocol = types.StringValue(policy.Protocol)
	}

	if policy.ConnectionStateType == "" {
		model.ConnectionStateType = types.StringValue("ALL")
	} else {
		model.ConnectionStateType = types.StringValue(policy.ConnectionStateType)
	}

	// Convert source
	model.Source = r.apiSourceToModel(ctx, &policy.Source)

	// Convert destination
	model.Destination = r.apiDestinationToModel(ctx, &policy.Destination)

	// Convert schedule
	model.Schedule = r.apiScheduleToModel(ctx, &policy.Schedule)
}

func (r *firewallPolicyResource) apiSourceToModel(
	ctx context.Context,
	source *unifi.FirewallPolicySource,
) types.Object {
	matchingTarget := source.MatchingTarget
	if matchingTarget == "" {
		matchingTarget = "ANY"
	}

	matchingTargetType := source.MatchingTargetType
	if matchingTargetType == "" {
		matchingTargetType = "ANY"
	}

	portMatchingType := source.PortMatchingType
	if portMatchingType == "" {
		portMatchingType = "ANY"
	}

	attrs := map[string]attr.Value{
		"zone_id":              types.StringValue(source.ZoneID),
		"matching_target":      types.StringValue(matchingTarget),
		"matching_target_type": types.StringValue(matchingTargetType),
		"port_matching_type":   types.StringValue(portMatchingType),
	}

	// Port
	if source.Port == 0 {
		attrs["port"] = types.Int64Null()
	} else {
		attrs["port"] = types.Int64Value(source.Port)
	}

	// Port group ID
	if source.PortGroupID == "" {
		attrs["port_group_id"] = types.StringNull()
	} else {
		attrs["port_group_id"] = types.StringValue(source.PortGroupID)
	}

	// IPs
	if len(source.IPs) == 0 {
		attrs["ips"] = types.SetNull(types.StringType)
	} else {
		ipList := make([]types.String, len(source.IPs))
		for i, ip := range source.IPs {
			ipList[i] = types.StringValue(ip)
		}
		ipsSet, _ := types.SetValueFrom(ctx, types.StringType, ipList)
		attrs["ips"] = ipsSet
	}

	// Network IDs
	if len(source.NetworkIDs) == 0 {
		attrs["network_ids"] = types.SetNull(types.StringType)
	} else {
		networkIDList := make([]types.String, len(source.NetworkIDs))
		for i, netID := range source.NetworkIDs {
			networkIDList[i] = types.StringValue(netID)
		}
		networkIDsSet, _ := types.SetValueFrom(ctx, types.StringType, networkIDList)
		attrs["network_ids"] = networkIDsSet
	}

	obj, _ := types.ObjectValue(firewallPolicyEndpointAttrTypes, attrs)
	return obj
}

func (r *firewallPolicyResource) apiDestinationToModel(
	ctx context.Context,
	dest *unifi.FirewallPolicyDestination,
) types.Object {
	matchingTarget := dest.MatchingTarget
	if matchingTarget == "" {
		matchingTarget = "ANY"
	}

	matchingTargetType := dest.MatchingTargetType
	if matchingTargetType == "" {
		matchingTargetType = "ANY"
	}

	portMatchingType := dest.PortMatchingType
	if portMatchingType == "" {
		portMatchingType = "ANY"
	}

	attrs := map[string]attr.Value{
		"zone_id":              types.StringValue(dest.ZoneID),
		"matching_target":      types.StringValue(matchingTarget),
		"matching_target_type": types.StringValue(matchingTargetType),
		"port_matching_type":   types.StringValue(portMatchingType),
	}

	// Port
	if dest.Port == 0 {
		attrs["port"] = types.Int64Null()
	} else {
		attrs["port"] = types.Int64Value(dest.Port)
	}

	// Port group ID
	if dest.PortGroupID == "" {
		attrs["port_group_id"] = types.StringNull()
	} else {
		attrs["port_group_id"] = types.StringValue(dest.PortGroupID)
	}

	// IPs
	if len(dest.IPs) == 0 {
		attrs["ips"] = types.SetNull(types.StringType)
	} else {
		ipList := make([]types.String, len(dest.IPs))
		for i, ip := range dest.IPs {
			ipList[i] = types.StringValue(ip)
		}
		ipsSet, _ := types.SetValueFrom(ctx, types.StringType, ipList)
		attrs["ips"] = ipsSet
	}

	// Network IDs
	if len(dest.NetworkIDs) == 0 {
		attrs["network_ids"] = types.SetNull(types.StringType)
	} else {
		networkIDList := make([]types.String, len(dest.NetworkIDs))
		for i, netID := range dest.NetworkIDs {
			networkIDList[i] = types.StringValue(netID)
		}
		networkIDsSet, _ := types.SetValueFrom(ctx, types.StringType, networkIDList)
		attrs["network_ids"] = networkIDsSet
	}

	obj, _ := types.ObjectValue(firewallPolicyEndpointAttrTypes, attrs)
	return obj
}

func (r *firewallPolicyResource) apiScheduleToModel(
	ctx context.Context,
	schedule *unifi.FirewallPolicySchedule,
) types.Object {
	mode := schedule.Mode
	if mode == "" {
		mode = "ALWAYS"
	}

	attrs := map[string]attr.Value{
		"mode":         types.StringValue(mode),
		"time_all_day": types.BoolValue(schedule.TimeAllDay),
	}

	// Date
	if schedule.Date == "" {
		attrs["date"] = types.StringNull()
	} else {
		attrs["date"] = types.StringValue(schedule.Date)
	}

	// Time range start
	if schedule.TimeRangeStart == "" {
		attrs["time_range_start"] = types.StringNull()
	} else {
		attrs["time_range_start"] = types.StringValue(schedule.TimeRangeStart)
	}

	// Time range end
	if schedule.TimeRangeEnd == "" {
		attrs["time_range_end"] = types.StringNull()
	} else {
		attrs["time_range_end"] = types.StringValue(schedule.TimeRangeEnd)
	}

	// Repeat on days
	if len(schedule.RepeatOnDays) == 0 {
		attrs["repeat_on_days"] = types.SetNull(types.StringType)
	} else {
		dayList := make([]types.String, len(schedule.RepeatOnDays))
		for i, day := range schedule.RepeatOnDays {
			dayList[i] = types.StringValue(day)
		}
		daysSet, _ := types.SetValueFrom(ctx, types.StringType, dayList)
		attrs["repeat_on_days"] = daysSet
	}

	obj, _ := types.ObjectValue(firewallPolicyScheduleAttrTypes, attrs)
	return obj
}
