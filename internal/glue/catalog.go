package glue

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/bilals12/iota/internal/lakepath"
)

type Catalog struct {
	client   *glue.Client
	database string
	bucket   string
}

func New(client *glue.Client, database, bucket string) *Catalog {
	return &Catalog{
		client:   client,
		database: database,
		bucket:   bucket,
	}
}

func (c *Catalog) EnsureDatabase(ctx context.Context) error {
	_, err := c.client.CreateDatabase(ctx, &glue.CreateDatabaseInput{
		DatabaseInput: &types.DatabaseInput{
			Name:        aws.String(c.database),
			Description: aws.String("iota data lake database"),
		},
	})
	if err != nil {
		var alreadyExists *types.AlreadyExistsException
		if _, ok := err.(*types.AlreadyExistsException); !ok {
			return fmt.Errorf("create database: %w", err)
		}
		_ = alreadyExists
	}
	return nil
}

func (c *Catalog) CreateTable(ctx context.Context, logType string) error {
	tableName := lakepath.TableSlug(logType)
	location := fmt.Sprintf("s3://%s/logs/%s/", c.bucket, tableName)

	input := &glue.CreateTableInput{
		DatabaseName: aws.String(c.database),
		TableInput: &types.TableInput{
			Name:        aws.String(tableName),
			Description: aws.String(fmt.Sprintf("iota table for %s logs", logType)),
			TableType:   aws.String("EXTERNAL_TABLE"),
			StorageDescriptor: &types.StorageDescriptor{
				Location:     aws.String(location),
				InputFormat:  aws.String("org.apache.hadoop.mapred.TextInputFormat"),
				OutputFormat: aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
				SerdeInfo: &types.SerDeInfo{
					SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
				},
				Columns: getColumnsForLogType(lakepath.CanonicalLogType(logType)),
			},
			PartitionKeys: getPartitionKeys(),
			Parameters: map[string]string{
				"classification": "json",
				"typeOfData":     "file",
			},
		},
	}

	_, err := c.client.CreateTable(ctx, input)
	if err != nil {
		if _, ok := err.(*types.AlreadyExistsException); !ok {
			return fmt.Errorf("create table: %w", err)
		}
	}

	return nil
}

func (c *Catalog) AddPartition(ctx context.Context, logType string, year, month, day, hour int) error {
	tableName := lakepath.TableSlug(logType)
	location := fmt.Sprintf("s3://%s/logs/%s/year=%d/month=%02d/day=%02d/hour=%02d/",
		c.bucket, tableName, year, month, day, hour)

	input := &glue.CreatePartitionInput{
		DatabaseName: aws.String(c.database),
		TableName:    aws.String(tableName),
		PartitionInput: &types.PartitionInput{
			Values: []string{
				fmt.Sprintf("%d", year),
				fmt.Sprintf("%02d", month),
				fmt.Sprintf("%02d", day),
				fmt.Sprintf("%02d", hour),
			},
			StorageDescriptor: &types.StorageDescriptor{
				Location:     aws.String(location),
				InputFormat:  aws.String("org.apache.hadoop.mapred.TextInputFormat"),
				OutputFormat: aws.String("org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"),
				SerdeInfo: &types.SerDeInfo{
					SerializationLibrary: aws.String("org.openx.data.jsonserde.JsonSerDe"),
				},
			},
		},
	}

	_, err := c.client.CreatePartition(ctx, input)
	if err != nil {
		if _, ok := err.(*types.AlreadyExistsException); !ok {
			return fmt.Errorf("create partition: %w", err)
		}
	}

	return nil
}

func getColumnsForLogType(logType string) []types.Column {
	baseColumns := []types.Column{
		{Name: aws.String("eventversion"), Type: aws.String("string")},
		{Name: aws.String("useridentity"), Type: aws.String("struct<type:string,principalid:string,arn:string,accountid:string>")},
		{Name: aws.String("eventtime"), Type: aws.String("timestamp")},
		{Name: aws.String("eventsource"), Type: aws.String("string")},
		{Name: aws.String("eventname"), Type: aws.String("string")},
		{Name: aws.String("awsregion"), Type: aws.String("string")},
		{Name: aws.String("sourceipaddress"), Type: aws.String("string")},
		{Name: aws.String("useragent"), Type: aws.String("string")},
		{Name: aws.String("errorcode"), Type: aws.String("string")},
		{Name: aws.String("errormessage"), Type: aws.String("string")},
		{Name: aws.String("requestparameters"), Type: aws.String("map<string,string>")},
		{Name: aws.String("responseelements"), Type: aws.String("map<string,string>")},
		{Name: aws.String("requestid"), Type: aws.String("string")},
		{Name: aws.String("eventid"), Type: aws.String("string")},
		{Name: aws.String("eventtype"), Type: aws.String("string")},
		{Name: aws.String("recipientaccountid"), Type: aws.String("string")},
		{Name: aws.String("resources"), Type: aws.String("array<struct<arn:string,accountid:string,type:string>>")},
	}

	switch logType {
	case "AWS.S3ServerAccess":
		return append(baseColumns, []types.Column{
			{Name: aws.String("bucket"), Type: aws.String("string")},
			{Name: aws.String("key"), Type: aws.String("string")},
			{Name: aws.String("operation"), Type: aws.String("string")},
			{Name: aws.String("remoteip"), Type: aws.String("string")},
			{Name: aws.String("requester"), Type: aws.String("string")},
			{Name: aws.String("httpstatus"), Type: aws.String("int")},
			{Name: aws.String("errorcode"), Type: aws.String("string")},
		}...)
	case "AWS.VPCFlow":
		return append(baseColumns, []types.Column{
			{Name: aws.String("srcaddr"), Type: aws.String("string")},
			{Name: aws.String("dstaddr"), Type: aws.String("string")},
			{Name: aws.String("srcport"), Type: aws.String("int")},
			{Name: aws.String("dstport"), Type: aws.String("int")},
			{Name: aws.String("protocol"), Type: aws.String("int")},
			{Name: aws.String("packets"), Type: aws.String("bigint")},
			{Name: aws.String("bytes"), Type: aws.String("bigint")},
			{Name: aws.String("action"), Type: aws.String("string")},
		}...)
	case "AWS.ALB":
		return append(baseColumns, []types.Column{
			{Name: aws.String("elb"), Type: aws.String("string")},
			{Name: aws.String("clientip"), Type: aws.String("string")},
			{Name: aws.String("targetip"), Type: aws.String("string")},
			{Name: aws.String("requestmethod"), Type: aws.String("string")},
			{Name: aws.String("requesturl"), Type: aws.String("string")},
			{Name: aws.String("elbstatuscode"), Type: aws.String("int")},
			{Name: aws.String("targetstatuscode"), Type: aws.String("int")},
			{Name: aws.String("useragent"), Type: aws.String("string")},
		}...)
	default:
		return baseColumns
	}
}

func getPartitionKeys() []types.Column {
	return []types.Column{
		{Name: aws.String("year"), Type: aws.String("int")},
		{Name: aws.String("month"), Type: aws.String("int")},
		{Name: aws.String("day"), Type: aws.String("int")},
		{Name: aws.String("hour"), Type: aws.String("int")},
	}
}
