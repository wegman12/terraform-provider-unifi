package unifi

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/ubiquiti-community/go-unifi/unifi"
)

var _ datasource.DataSource = &firewallZoneDataSource{}

func NewFirewallZoneDataSource() datasource.DataSource {
	return &firewallZoneDataSource{}
}

type firewallZoneDataSource struct {
	client *Client
}

type firewallZoneDataSourceModel struct {
	ID          types.String `tfsdk:"id"`
	Site        types.String `tfsdk:"site"`
	Name        types.String `tfsdk:"name"`
	ZoneKey     types.String `tfsdk:"zone_key"`
	NetworkIDs  types.Set    `tfsdk:"network_ids"`
	DefaultZone types.Bool   `tfsdk:"default_zone"`
}

func (d *firewallZoneDataSource) Metadata(
	ctx context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_firewall_zone"
}

func (d *firewallZoneDataSource) Schema(
	ctx context.Context,
	req datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Data source for looking up UniFi Zone-Based Firewall (ZBF) zones. " +
			"Zones are used to group networks for firewall policy rules.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The ID of the firewall zone. Specify either `id` or `name` to look up the zone.",
				Optional:            true,
				Computed:            true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(path.Expressions{
						path.MatchRoot("name"),
					}...),
				},
			},
			"site": schema.StringAttribute{
				MarkdownDescription: "The name of the site to look up the zone in.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name of the firewall zone to look up (e.g., \"External\", \"Internal\", \"DMZ\").",
				Optional:            true,
				Computed:            true,
			},
			"zone_key": schema.StringAttribute{
				MarkdownDescription: "The internal zone key identifier.",
				Computed:            true,
			},
			"network_ids": schema.SetAttribute{
				MarkdownDescription: "The IDs of networks associated with this zone.",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"default_zone": schema.BoolAttribute{
				MarkdownDescription: "Whether this is a default system zone.",
				Computed:            true,
			},
		},
	}
}

func (d *firewallZoneDataSource) Configure(
	ctx context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf(
				"Expected *Client, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)
		return
	}

	d.client = client
}

func (d *firewallZoneDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data firewallZoneDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	site := data.Site.ValueString()
	if site == "" {
		site = d.client.Site
	}

	// List all zones from API
	zones, err := d.client.ListFirewallZone(ctx, site)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Firewall Zones",
			"Could not read firewall zones: "+err.Error(),
		)
		return
	}

	// Find zone by ID or name
	var foundZone *unifi.FirewallZone
	lookupByID := !data.ID.IsNull() && !data.ID.IsUnknown()

	if lookupByID {
		id := data.ID.ValueString()
		for _, zone := range zones {
			if zone.ID == id {
				foundZone = &zone
				break
			}
		}
		if foundZone == nil {
			resp.Diagnostics.AddError(
				"Firewall Zone Not Found",
				fmt.Sprintf("Firewall zone with ID %q not found", id),
			)
			return
		}
	} else {
		name := data.Name.ValueString()
		for _, zone := range zones {
			if zone.Name == name {
				foundZone = &zone
				break
			}
		}
		if foundZone == nil {
			resp.Diagnostics.AddError(
				"Firewall Zone Not Found",
				fmt.Sprintf("Firewall zone with name %q not found", name),
			)
			return
		}
	}

	// Set state from found zone
	data.ID = types.StringValue(foundZone.ID)
	data.Site = types.StringValue(site)
	data.Name = types.StringValue(foundZone.Name)
	data.DefaultZone = types.BoolValue(foundZone.DefaultZone)

	if foundZone.ZoneKey == "" {
		data.ZoneKey = types.StringNull()
	} else {
		data.ZoneKey = types.StringValue(foundZone.ZoneKey)
	}

	// Convert network IDs slice to set
	if len(foundZone.NetworkIDs) == 0 {
		data.NetworkIDs = types.SetNull(types.StringType)
	} else {
		networkIDList := make([]types.String, len(foundZone.NetworkIDs))
		for i, netID := range foundZone.NetworkIDs {
			networkIDList[i] = types.StringValue(netID)
		}
		networkIDsSet, diags := types.SetValueFrom(ctx, types.StringType, networkIDList)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		data.NetworkIDs = networkIDsSet
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
