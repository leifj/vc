package apiv1

import (
	"context"
	"vc/internal/gen/status/apiv1_status"
)

// Health returns the health status
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return &apiv1_status.StatusReply{
		Data: &apiv1_status.StatusReply_Data{
			ServiceName: "verifier-proxy",
			Status:      "healthy",
			BuildVariables: &apiv1_status.BuildVariables{
				Version: "0.1.0",
			},
		},
	}, nil
}
