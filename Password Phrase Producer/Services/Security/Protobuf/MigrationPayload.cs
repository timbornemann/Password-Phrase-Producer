using Google.Protobuf;
using Google.Protobuf.Collections;
using Google.Protobuf.Reflection;
using System;

namespace Password_Phrase_Producer.Services.Security.Protobuf;

/// <summary>
/// Manually implemented Protobuf classes for Google Authenticator Migration Payload.
/// Format reverse-engineered from OtpMigration.proto
/// </summary>
public sealed class MigrationPayload : IMessage<MigrationPayload>
{
    private static readonly MessageParser<MigrationPayload> _parser = new MessageParser<MigrationPayload>(() => new MigrationPayload());
    public static MessageParser<MigrationPayload> Parser => _parser;

    public MessageDescriptor Descriptor => null!; // Not using full reflection

    public RepeatedField<OtpParameters> OtpParameters { get; } = new RepeatedField<OtpParameters>();
    public const int OtpParametersFieldNumber = 1;

    public int Version { get; set; }
    public const int VersionFieldNumber = 2;

    public int BatchSize { get; set; }
    public const int BatchSizeFieldNumber = 3;

    public int BatchIndex { get; set; }
    public const int BatchIndexFieldNumber = 4;

    public int BatchId { get; set; }
    public const int BatchIdFieldNumber = 5;

    public void WriteTo(CodedOutputStream output)
    {
        OtpParameters.WriteTo(output, _otpParametersCodec);
        if (Version != 0)
        {
            output.WriteRawTag(16);
            output.WriteInt32(Version);
        }
        if (BatchSize != 0)
        {
            output.WriteRawTag(24);
            output.WriteInt32(BatchSize);
        }
        if (BatchIndex != 0)
        {
            output.WriteRawTag(32);
            output.WriteInt32(BatchIndex);
        }
        if (BatchId != 0)
        {
            output.WriteRawTag(40);
            output.WriteInt32(BatchId);
        }
    }

    public int CalculateSize()
    {
        int size = 0;
        size += OtpParameters.CalculateSize(_otpParametersCodec);
        if (Version != 0) size += 1 + CodedOutputStream.ComputeInt32Size(Version);
        if (BatchSize != 0) size += 1 + CodedOutputStream.ComputeInt32Size(BatchSize);
        if (BatchIndex != 0) size += 1 + CodedOutputStream.ComputeInt32Size(BatchIndex);
        if (BatchId != 0) size += 1 + CodedOutputStream.ComputeInt32Size(BatchId);
        return size;
    }

    public void MergeFrom(MigrationPayload other)
    {
        if (other == null) return;
        OtpParameters.Add(other.OtpParameters);
        if (other.Version != 0) Version = other.Version;
        if (other.BatchSize != 0) BatchSize = other.BatchSize;
        if (other.BatchIndex != 0) BatchIndex = other.BatchIndex;
        if (other.BatchId != 0) BatchId = other.BatchId;
    }

    public void MergeFrom(CodedInputStream input)
    {
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            switch (tag)
            {
                case 10: { OtpParameters.AddEntriesFrom(input, _otpParametersCodec); break; }
                case 16: { Version = input.ReadInt32(); break; }
                case 24: { BatchSize = input.ReadInt32(); break; }
                case 32: { BatchIndex = input.ReadInt32(); break; }
                case 40: { BatchId = input.ReadInt32(); break; }
                default: { input.SkipLastField(); break; }
            }
        }
    }
    
    // Helper codec for repeated field
    private static readonly FieldCodec<OtpParameters> _otpParametersCodec = FieldCodec.ForMessage(10, Password_Phrase_Producer.Services.Security.Protobuf.OtpParameters.Parser);

    public bool Equals(MigrationPayload? other)
    {
        if (ReferenceEquals(other, null)) return false;
        if (ReferenceEquals(other, this)) return true;
        if (!OtpParameters.Equals(other.OtpParameters)) return false;
        if (Version != other.Version) return false;
        if (BatchSize != other.BatchSize) return false;
        if (BatchIndex != other.BatchIndex) return false;
        if (BatchId != other.BatchId) return false;
        return true;
    }

    public override bool Equals(object? obj) => Equals(obj as MigrationPayload);
    public override int GetHashCode() => 0; // Simplified
    public MigrationPayload Clone()
    {
        var clone = new MigrationPayload();
        clone.MergeFrom(this);
        return clone;
    }
}

public sealed class OtpParameters : IMessage<OtpParameters>
{
    private static readonly MessageParser<OtpParameters> _parser = new MessageParser<OtpParameters>(() => new OtpParameters());
    public static MessageParser<OtpParameters> Parser => _parser;

    public MessageDescriptor Descriptor => null!;

    public ByteString Secret { get; set; } = ByteString.Empty;
    public const int SecretFieldNumber = 1;

    public string Name { get; set; } = "";
    public const int NameFieldNumber = 2;

    public string Issuer { get; set; } = "";
    public const int IssuerFieldNumber = 3;

    public Algorithm Algorithm { get; set; }
    public const int AlgorithmFieldNumber = 4;

    public int Digits { get; set; }
    public const int DigitsFieldNumber = 5;

    public OtType Type { get; set; }
    public const int TypeFieldNumber = 6;

    public long Counter { get; set; }
    public const int CounterFieldNumber = 7;

    public void WriteTo(CodedOutputStream output)
    {
        // Not implemented for serialization as we only need reading
    }

    public int CalculateSize()
    {
        // Not implemented
        return 0;
    }

    public void MergeFrom(OtpParameters other)
    {
        // Not implemented
    }

    public void MergeFrom(CodedInputStream input)
    {
        uint tag;
        while ((tag = input.ReadTag()) != 0)
        {
            switch (tag)
            {
                case 10: { Secret = input.ReadBytes(); break; }
                case 18: { Name = input.ReadString(); break; }
                case 26: { Issuer = input.ReadString(); break; }
                case 32: { Algorithm = (Algorithm)input.ReadEnum(); break; }
                case 40: { Digits = input.ReadInt32(); break; }
                case 48: { Type = (OtType)input.ReadEnum(); break; }
                case 56: { Counter = input.ReadInt64(); break; }
                default: { input.SkipLastField(); break; }
            }
        }
    }

    public bool Equals(OtpParameters? other) => false; // Simplified
    public override bool Equals(object? obj) => false;
    public override int GetHashCode() => 0; 
    public OtpParameters Clone() => new OtpParameters(); 
}

public enum Algorithm
{
    Unspecified = 0,
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
    Md5 = 4
}

public enum OtType
{
    Unspecified = 0,
    Hotp = 1,
    Totp = 2
}
